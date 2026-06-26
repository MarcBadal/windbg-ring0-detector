#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  ring0_detector.py
#  Detección automatizada de comportamientos maliciosos en Ring 0 (kernel
#  de Windows x64) mediante PyKd + WinDbg.
#
#
#  El script automatiza la detección manual descrita en la guía (README.md)
#  para cuatro técnicas de rootkit tratadas en el módulo:
#     1) SSDT Hooking  -> entradas de KiServiceTable que resuelven FUERA de nt
#     2) IDT Hooking    -> ISRs que apuntan a un módulo no confiable (keylogger)
#     3) DKOM           -> procesos ocultos (vista doble: lista enlazada vs CID)
#     4) Red            -> hooks de dispatch en drivers de red (tcpip/afd/...)
#
#
#  Uso típico (sesión de kernel debugging ya conectada en WinDbg):
#       0:kd> .load pykd.pyd          ; (o .load pykd)
#       0:kd> !py C:\ruta\ring0_detector.py
#
#  Sobre un volcado de memoria:
#       python ring0_detector.py C:\ruta\MEMORY.DMP
#
#  Requisitos: Windows x64, símbolos del kernel cargados (.reload /f).
# =============================================================================

import sys
import re

try:
    import pykd
except ImportError:
    print("[!] No se encontró el módulo pykd. Ejecútalo desde WinDbg con !py "
          "o instala pykd para depuración de volcados.")
    sys.exit(1)

# Canonical: las direcciones del kernel en x64 están en el rango canónico alto.
KERNEL_MIN = 0xFFFF000000000000
IRP_MJ_MAXIMUM_FUNCTION = 27  # MajorFunction[0..27] -> 28 entradas

# Módulos considerados "de confianza" como destino legítimo de un dispatch o ISR.
# nt = ntoskrnl, hal = capa de abstracción, fltmgr = filter manager (legítimo).
TRUSTED_MODULES = {"nt", "ntoskrnl", "hal", "fltmgr"}

# -----------------------------------------------------------------------------
# Utilidades de salida
# -----------------------------------------------------------------------------
def header(title):
    print("\n" + "=" * 78)
    print("  " + title)
    print("=" * 78)

def ok(msg):       print("  [OK]   " + msg)
def alert(msg):    print("  [!!!]  " + msg)
def info(msg):     print("  [ * ]  " + msg)
def warn(msg):     print("  [ ? ]  " + msg)


# -----------------------------------------------------------------------------
# Mapa de módulos cargados: (nombre, inicio, fin)
# Es la primitiva central de detección de hooks: "¿este puntero de código cae
# dentro de la imagen de algún driver/módulo legítimo cargado?"
# -----------------------------------------------------------------------------
def build_module_map():
    mods = []
    try:
        for m in pykd.getModulesList():
            # pykd expone name/begin/end como métodos o como propiedades según versión
            name  = m.name()  if callable(getattr(m, "name", None))  else m.name
            begin = m.begin() if callable(getattr(m, "begin", None)) else m.begin
            end   = m.end()   if callable(getattr(m, "end", None))   else m.end
            mods.append((str(name).lower(), int(begin), int(end)))
    except Exception:
        # Fallback: parsear la salida de "lm n" (start end name ...)
        for line in pykd.dbgCommand("lm n").splitlines():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    b = int(parts[0].replace("`", ""), 16)
                    e = int(parts[1].replace("`", ""), 16)
                    mods.append((parts[2].lower(), b, e))
                except ValueError:
                    continue
    return mods


def module_for_address(addr, modmap):
    """Devuelve el nombre del módulo que contiene 'addr', o None si no pertenece
    a ninguna imagen cargada (lo cual es ya de por sí muy sospechoso en Ring 0)."""
    for name, begin, end in modmap:
        if begin <= addr < end:
            return name
    return None


def sym(addr):
    """Símbolo más cercano (módulo!función+offset) para dar contexto legible."""
    try:
        return pykd.findSymbol(addr)
    except Exception:
        return hex(addr)


def read_image_name(eproc_addr):
    """Lee EPROCESS.ImageFileName (UCHAR[15]) de forma robusta."""
    try:
        p = pykd.typedVar("nt!_EPROCESS", eproc_addr)
        name_addr = p.ImageFileName.getAddress()
        raw = bytes(pykd.loadBytes(name_addr, 15))
        return raw.split(b"\x00")[0].decode("latin-1", "replace")
    except Exception:
        return "?"


# -----------------------------------------------------------------------------
# 1) SSDT HOOKING
# -----------------------------------------------------------------------------
# La SSDT (KiServiceTable) almacena, en x64, OFFSETS relativos de 4 bytes.
# La dirección absoluta de cada rutina se obtiene con:
#       rutina = KiServiceTable + (offset_con_signo >> 4)
# Una entrada legítima SIEMPRE
# resuelve dentro de la imagen de 'nt'. Si resuelve a otro módulo => HOOK.
# -----------------------------------------------------------------------------
def check_ssdt(modmap):
    header("1) SSDT Hooking  (KiServiceTable)")
    suspicious = 0
    try:
        base  = pykd.getOffset("nt!KiServiceTable")
        limit = pykd.ptrDWord(pykd.getOffset("nt!KiServiceLimit"))
    except Exception:
        # Fallback vía KeServiceDescriptorTable: {Base(0x0), Count(0x8), Limit(0x10)}
        try:
            sdt   = pykd.getOffset("nt!KeServiceDescriptorTable")
            base  = pykd.ptrQWord(sdt)
            limit = pykd.ptrDWord(sdt + 0x10)
        except Exception as e:
            warn("No se pudo localizar la SSDT (¿símbolos cargados? .reload /f): %s" % e)
            return

    info("KiServiceTable = 0x%x   (%d syscalls)" % (base, limit))
    for i in range(limit):
        try:
            raw = pykd.ptrDWord(base + i * 4)          # offset de 4 bytes (sin signo)
            if raw >= 0x80000000:                      # convertir a 32 bits con signo
                raw -= 0x100000000
            routine = base + (raw >> 4)                # >> aritmético en Python
            owner = module_for_address(routine, modmap)
            if owner != "nt":
                suspicious += 1
                alert("Syscall #%d -> 0x%x  módulo=%s  %s"
                      % (i, routine, owner or "DESCONOCIDO", sym(routine)))
        except Exception:
            continue

    if suspicious == 0:
        ok("Todas las entradas de la SSDT resuelven dentro de nt. Sin hooks.")
    else:
        alert("%d entrada(s) de la SSDT apuntan fuera de nt -> posible SSDT Hooking."
              % suspicious)


# -----------------------------------------------------------------------------
# 2) IDT HOOKING
# -----------------------------------------------------------------------------
# Cada entrada de la IDT (_KIDTENTRY64) referencia una ISR. Para detectar
# hooks de forma robusta parseamos "!idt -a" y verificamos que cada handler
# pertenece a un módulo de confianza. La interrupción de teclado debe terminar
# en i8042prt/kbdclass; si apunta a otro driver => posible keylogger por IDT.
# -----------------------------------------------------------------------------
def check_idt(modmap):
    header("2) IDT Hooking  (Interrupt Descriptor Table)")
    suspicious = 0
    try:
        out = pykd.dbgCommand("!idt -a")
    except Exception as e:
        warn("No se pudo ejecutar '!idt -a': %s" % e)
        return

    # Línea típica en x64:
    #   80: fffff803`967bb6c0 i8042prt!I8042KeyboardInterruptService (KINTERRUPT fffe6005`753bc80)
    #
    # OJO (clave en x64): la DIRECCIÓN que muestra !idt (col. 2) NO suele ser la ISR
    # del driver, sino un THUNK dentro de 'nt' (KiIsrThunk / KiInterruptDispatch). La
    # ISR REAL está en KINTERRUPT.ServiceRoutine. Por eso NO comparamos "módulo del
    # símbolo" contra "módulo de la dirección" (eso genera 1 falso positivo por cada
    # interrupción de dispositivo): resolvemos la ServiceRoutine del KINTERRUPT y
    # comprobamos ESA dirección contra el mapa de módulos cargados.
    line_re = re.compile(r"^\s*([0-9a-fA-F]{1,3}):\s+([0-9a-fA-F`]+)\s+(\S+)")
    kint_re = re.compile(r"KINTERRUPT\s+([0-9a-fA-F`]+)")
    keyboard_seen = False

    for line in out.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        vector = m.group(1)
        symbol = m.group(3)

        # Dirección de la ISR real:
        #   - si la línea referencia un KINTERRUPT, leemos su ServiceRoutine (lo correcto)
        #   - si no, usamos la dirección literal de la entrada (vectores sin KINTERRUPT)
        isr = None
        km = kint_re.search(line)
        if km:
            try:
                kint = int(km.group(1).replace("`", ""), 16)
                isr = int(pykd.typedVar("nt!_KINTERRUPT", kint).ServiceRoutine)
            except Exception:
                isr = None
        if isr is None:
            try:
                isr = int(m.group(2).replace("`", ""), 16)
            except ValueError:
                continue

        owner = module_for_address(isr, modmap)

        # Vector de teclado: la ISR real debe pertenecer a i8042prt/kbdclass.
        if "i8042" in symbol.lower() or "kbdclass" in symbol.lower():
            keyboard_seen = True
            if owner not in ("i8042prt", "kbdclass"):
                suspicious += 1
                alert("Vector 0x%s (teclado) -> ISR en %s (esperado i8042prt/kbdclass)"
                      " => POSIBLE KEYLOGGER  %s"
                      % (vector, owner or "DESCONOCIDO", sym(isr)))
            continue

        # Regla general robusta: la ISR real no cae en NINGÚN módulo cargado.
        # (un hook por IDT que redirija a shellcode/driver no firmado caería aquí)
        if isr and owner is None:
            suspicious += 1
            alert("Vector 0x%s -> ISR 0x%x NO pertenece a ningún módulo cargado  (%s)"
                  % (vector, isr, symbol))

    if not keyboard_seen:
        info("No se localizó la ISR de teclado en !idt (¿teclado USB? -> stack "
             "hidclass/kbdhid en vez de i8042prt).")
    if suspicious == 0:
        ok("Todas las ISR (resueltas vía KINTERRUPT) caen en módulos cargados. Sin hooks.")
    else:
        alert("%d anomalía(s) en la IDT -> posible IDT Hooking." % suspicious)


# -----------------------------------------------------------------------------
# 3) DKOM - PROCESOS OCULTOS
# -----------------------------------------------------------------------------
# El DKOM desvincula un EPROCESS de la lista doblemente enlazada
# ActiveProcessLinks (lo que oculta el proceso de !process / Task Manager) pero
# el objeto sigue existiendo. Estrategia de "vista cruzada":
#    Vista A (manipulable) : recorrido de ActiveProcessLinks.
#    Vista B (independiente): enumeración de nt!PspCidTable.
# Un proceso presente en B pero ausente en A está OCULTO por DKOM.
# Además se verifica la integridad Flink/Blink de la propia lista.
# -----------------------------------------------------------------------------
def walk_active_process_links():
    head = pykd.getOffset("nt!PsActiveProcessHead")
    off  = pykd.typeInfo("nt!_EPROCESS").fieldOffset("ActiveProcessLinks")
    procs = {}          # pid -> (eproc_addr, name)
    broken = []         # incoherencias Flink/Blink
    node = pykd.ptrQWord(head)
    guard = 0
    while node != head and guard < 100000:
        guard += 1
        eproc = node - off
        try:
            pid = int(pykd.typedVar("nt!_EPROCESS", eproc).UniqueProcessId)
            name = read_image_name(eproc)
            procs[pid] = (eproc, name)
        except Exception:
            pass
        # Integridad de la doble lista: node.Flink.Blink debe ser node
        flink = pykd.ptrQWord(node)
        try:
            if pykd.ptrQWord(flink + 8) != node:
                broken.append(node)
        except Exception:
            pass
        node = flink
    return procs, broken


def walk_pspcidtable():
    """Vista independiente vía la tabla de Client IDs. Devuelve {pid: eproc_addr}.
    Usa offsets resueltos en tiempo de ejecución y degrada con elegancia: si la
    estructura del build no coincide, devuelve None en lugar de fallar."""
    try:
        cid_ptr = pykd.getOffset("nt!PspCidTable")
        table   = pykd.ptrQWord(cid_ptr)
        ht      = pykd.typedVar("nt!_HANDLE_TABLE", table)
        table_code = int(ht.TableCode)
        levels = table_code & 7
        base   = table_code & ~7
        body_off = pykd.typeInfo("nt!_OBJECT_HEADER").fieldOffset("Body")
    except Exception as e:
        warn("No se pudo inicializar PspCidTable: %s" % e)
        return None

    PAGE, ENTRY = 0x1000, 0x10

    def decode(entry_addr):
        # Decodificación del puntero al objeto a partir de _HANDLE_TABLE_ENTRY.
        try:
            opb = int(pykd.typedVar("nt!_HANDLE_TABLE_ENTRY", entry_addr).ObjectPointerBits)
            if opb == 0:
                return None
            objhdr = (opb << 4) | KERNEL_MIN
        except Exception:
            low = pykd.ptrQWord(entry_addr)
            if low == 0:
                return None
            objhdr = ((low >> 20) << 4) | KERNEL_MIN
        if objhdr < KERNEL_MIN:
            return None
        return objhdr + body_off          # cuerpo del objeto (EPROCESS / ETHREAD / ...)

    def leaf(p):
        out = []
        for i in range(0, PAGE, ENTRY):
            o = decode(p + i)
            if o:
                out.append(o)
        return out

    candidates = []
    try:
        if levels == 0:
            candidates += leaf(base)
        elif levels == 1:
            for i in range(0, PAGE, 8):
                lp = pykd.ptrQWord(base + i)
                if lp:
                    candidates += leaf(lp)
        else:
            for i in range(0, PAGE, 8):
                mid = pykd.ptrQWord(base + i)
                if not mid:
                    continue
                for j in range(0, PAGE, 8):
                    lp = pykd.ptrQWord(mid + j)
                    if lp:
                        candidates += leaf(lp)
    except Exception as e:
        warn("Error recorriendo PspCidTable: %s" % e)
        return None

    # Filtramos a objetos que "parecen" EPROCESS (la tabla mezcla procesos e hilos).
    # Heurística: PID múltiplo de 4, > 0 y nombre de imagen imprimible.
    procs = {}
    for c in candidates:
        try:
            pid = int(pykd.typedVar("nt!_EPROCESS", c).UniqueProcessId)
            if pid <= 0 or pid % 4 != 0 or pid > 0x40000000:
                continue
            name = read_image_name(c)
            if name and all(32 <= ord(ch) < 127 for ch in name):
                procs[pid] = c
        except Exception:
            continue
    return procs


def check_dkom():
    header("3) DKOM  (procesos ocultos)")
    try:
        listed, broken = walk_active_process_links()
    except Exception as e:
        warn("No se pudo recorrer ActiveProcessLinks: %s" % e)
        return

    info("Procesos en la lista enlazada (ActiveProcessLinks): %d" % len(listed))
    if broken:
        alert("%d nodo(s) con punteros Flink/Blink incoherentes -> manipulación de lista."
              % len(broken))

    cid = walk_pspcidtable()
    if not cid:          # None o diccionario vacío -> la vista independiente NO funcionó
        warn("La vista independiente (PspCidTable) no devolvió procesos en este build. "
             "La verificación cruzada NO es concluyente (la decodificación de "
             "_HANDLE_TABLE_ENTRY depende de la versión). Realiza la verificación manual "
             "de la guía (sección DKOM) o ajusta el decodificador a tu build.")
        return

    info("Procesos vistos vía PspCidTable (vista independiente): %d" % len(cid))

    # Salvaguarda anti-falso-negativo: si la vista independiente ve muchísimos menos
    # procesos que la lista enlazada, lo más probable es que la enumeración haya
    # fallado parcialmente; en ese caso un "sin discrepancias" sería un falso "limpio".
    if len(cid) < max(1, len(listed) // 2):
        warn("La vista independiente ve muchos menos procesos que la lista enlazada "
             "(%d vs %d): enumeración incompleta -> resultado NO concluyente."
             % (len(cid), len(listed)))
        return

    hidden = [pid for pid in cid if pid not in listed]
    if not hidden:
        ok("Sin discrepancias: ningún proceso oculto detectado.")
    else:
        for pid in hidden:
            name = read_image_name(cid[pid])
            alert("PROCESO OCULTO  PID=%d  EPROCESS=0x%x  nombre=%s  -> DKOM"
                  % (pid, cid[pid], name))


# -----------------------------------------------------------------------------
# 4) RED - HOOKS DE DISPATCH EN DRIVERS DE RED
# -----------------------------------------------------------------------------
# Para ocultar/manipular conexiones y puertos, un rootkit suele "hookear" las
# rutinas de dispatch (DRIVER_OBJECT.MajorFunction) de los drivers de red. Cada
# puntero de MajorFunction debe apuntar a la propia imagen del driver, a nt
# (IopInvalidDeviceRequest) o a fltmgr. Cualquier otro destino => dispatch hook.
# Adicionalmente se intenta volcar las conexiones activas con !netstat si está
# disponible.
# -----------------------------------------------------------------------------
def get_driver_object(name):
    try:
        out = pykd.dbgCommand("!drvobj %s" % name)
    except Exception:
        return None
    m = re.search(r"Driver object \(([0-9a-fA-F`]+)\)", out)
    if not m:
        return None
    try:
        return int(m.group(1).replace("`", ""), 16)
    except ValueError:
        return None


def is_valid_driver_object(addr):
    """Comprueba que 'addr' es realmente un _DRIVER_OBJECT y no otra cosa (p. ej.
    netio.sys es una librería del kernel SIN DRIVER_OBJECT clásico; !drvobj puede
    devolver una dirección que NO es un objeto válido, y recorrer su MajorFunction
    leería bytes de la cabecera PE como si fueran punteros -> falsos positivos).

    Validación: el campo Type del _OBJECT_HEADER previo debe ser 4 (IO_TYPE_DRIVER)
    y, como respaldo, DriverStart debe caer en un módulo cargado."""
    try:
        # Type del objeto: leemos el _OBJECT_HEADER que precede al cuerpo.
        # En x64 el campo DriverObject.Type vale 4 para un driver legítimo.
        t = int(pykd.typedVar("nt!_DRIVER_OBJECT", addr).Type)
        if t == 4:
            return True
    except Exception:
        pass
    # Respaldo: que DriverStart apunte a una imagen cargada y DriverSize sea creíble.
    try:
        drv   = pykd.typedVar("nt!_DRIVER_OBJECT", addr)
        start = int(drv.DriverStart)
        size  = int(drv.DriverSize)
        return size >= 0x1000 and module_for_address(start, build_module_map()) is not None
    except Exception:
        return False


def check_network(modmap):
    header("4) Red  (dispatch hooks en drivers de red + conexiones)")
    # netio.sys es una librería del kernel: no expone un DRIVER_OBJECT con tabla
    # MajorFunction clásica, por lo que no se analiza aquí (is_valid_driver_object
    # lo descartaría igualmente). Los drivers con dispatch real son los siguientes.
    net_drivers = ["tcpip", "afd", "ndis", "http"]
    suspicious = 0

    for drvname in net_drivers:
        addr = get_driver_object(drvname)
        if not addr:
            continue
        if not is_valid_driver_object(addr):
            info("Driver \\Driver\\%s  no expone un _DRIVER_OBJECT válido "
                 "(p. ej. librería del kernel); se omite." % drvname)
            continue
        try:
            drv   = pykd.typedVar("nt!_DRIVER_OBJECT", addr)
            start = int(drv.DriverStart)
            size  = int(drv.DriverSize)
        except Exception:
            continue

        own = module_for_address(start, modmap)
        # ¿Es creíble el rango de imagen leído de DriverStart/DriverSize?
        # (a veces se lee mal, p. ej. netio -> [0x40-0x40]); si no, validamos por módulo.
        valid_range = (size >= 0x1000 and own is not None)
        if valid_range:
            info("Driver \\Driver\\%s  imagen=%s  [0x%x - 0x%x]"
                 % (drvname, own, start, start + size))
        else:
            info("Driver \\Driver\\%s  (DriverStart/Size no fiables; se valida por "
                 "módulo destino del dispatch)" % drvname)

        for i in range(IRP_MJ_MAXIMUM_FUNCTION + 1):
            try:
                h = int(drv.MajorFunction[i])
            except Exception:
                continue
            if h == 0:
                continue
            owner   = module_for_address(h, modmap)
            in_self = valid_range and (start <= h < start + size)
            # Legítimo si el dispatch cae: (a) en la propia imagen del driver,
            # (b) en nt/hal/fltmgr, (c) en el módulo que es la propia imagen (own),
            # o (d) en un módulo cuyo NOMBRE coincide con el del driver (netio->netio).
            legit = (in_self
                     or owner in TRUSTED_MODULES
                     or (own is not None and owner == own)
                     or (owner is not None and owner == drvname))
            if not legit:
                suspicious += 1
                alert("%s MajorFunction[%d] -> 0x%x  módulo=%s  %s  (DISPATCH HOOK)"
                      % (drvname, i, h, owner or "DESCONOCIDO", sym(h)))

    if suspicious == 0:
        ok("Rutinas de dispatch de los drivers de red intactas. Sin hooks.")
    else:
        alert("%d hook(s) de dispatch en drivers de red -> manipulación del stack."
              % suspicious)

    # Conexiones activas (best-effort; la extensión !netstat no siempre existe).
    try:
        ns = pykd.dbgCommand("!netstat")
        if ns and "TCP" in ns.upper():
            info("Conexiones activas (!netstat):")
            for line in ns.splitlines():
                if line.strip():
                    print("        " + line.strip())
        else:
            info("!netstat no disponible. Usa el método manual de la guía "
                 "(estructuras de tcpip.sys) para enumerar conexiones.")
    except Exception:
        info("!netstat no disponible. Usa el método manual de la guía "
             "(estructuras de tcpip.sys) para enumerar conexiones.")


# -----------------------------------------------------------------------------
# Orquestación
# -----------------------------------------------------------------------------
def main():
    # Permite cargar un volcado si se pasa por argumento (ejecución standalone).
    if len(sys.argv) > 1:
        try:
            pykd.loadDump(sys.argv[1])
            print("[*] Volcado cargado: %s" % sys.argv[1])
        except Exception as e:
            print("[!] No se pudo cargar el volcado: %s" % e)
            return

    print("#" * 78)
    print("#  ring0_detector.py - Detección de comportamientos maliciosos en Ring 0")
    print("#  Módulo 10 | Reversing de Sistemas Windows")
    print("#" * 78)

    # Comprobaciones previas
    try:
        if not pykd.isKernelDebugging():
            warn("No parece una sesión de KERNEL debugging. Resultados no fiables.")
    except Exception:
        pass
    try:
        pykd.getOffset("nt!PsActiveProcessHead")
    except Exception:
        alert("Símbolos del kernel no resueltos. Ejecuta '.reload /f' y configura "
              "el symbol path (srv*) antes de lanzar el script.")
        return

    modmap = build_module_map()
    info("Módulos cargados mapeados: %d" % len(modmap))

    check_ssdt(modmap)
    check_idt(modmap)
    check_dkom()
    check_network(modmap)

    header("Análisis finalizado")
    print("  Revisa las líneas marcadas con [!!!]: indican anomalías candidatas")
    print("  a actividad de rootkit en Ring 0. Contrástalas manualmente con WinDbg.\n")


if __name__ == "__main__":
    main()
