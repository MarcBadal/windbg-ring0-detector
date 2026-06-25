# Detección de malware en Ring 0 con WinDbg y automatización con PyKd


> Documento guía orientado a explicar, estudiar y usar **WinDbg** para detectar
> actividades maliciosas ejecutadas en **Ring 0** (modo kernel) en sistemas
> Windows x64, junto con un script en **PyKd** que automatiza dicha detección.

---

## Tabla de contenidos

1. [Objetivo y alcance](#1-objetivo-y-alcance)
2. [Fundamentos: por qué importa el Ring 0](#2-fundamentos-por-qué-importa-el-ring-0)
3. [Estructuras del kernel relevantes](#3-estructuras-del-kernel-relevantes)
4. [Preparación del entorno de depuración](#4-preparación-del-entorno-de-depuración)
5. [Comandos de WinDbg para la detección](#5-comandos-de-windbg-para-la-detección)
6. [Detección manual por técnica](#6-detección-manual-por-técnica)
   - [6.1 SSDT Hooking](#61-ssdt-hooking)
   - [6.2 IDT Hooking (keylogger)](#62-idt-hooking-keylogger)
   - [6.3 DKOM: procesos ocultos](#63-dkom-procesos-ocultos)
   - [6.4 Red: conexiones, puertos y dispatch hooks](#64-red-conexiones-puertos-y-dispatch-hooks)
7. [Automatización con scripts](#7-automatización-con-scripts)
8. [El script `ring0_detector.py`](#8-el-script-ring0_detectorpy)
9. [Validación contra línea base limpia y corrección de falsos positivos](#9-validación-contra-línea-base-limpia-y-corrección-de-falsos-positivos)
10. [Limitaciones y consideraciones](#10-limitaciones-y-consideraciones)
11. [Estructura del repositorio y entrega](#11-estructura-del-repositorio-y-entrega)
12. [Referencias](#12-referencias)

---

## 1. Objetivo y alcance

El objetivo es doble: por un lado, **explicar de forma teórica y
práctica** cómo se utiliza WinDbg para detectar comportamientos que un rootkit
puede desplegar en modo kernel; y por otro, **automatizar esa detección** con un
pequeño script para no tener que repetir manualmente las consultas.

Nos centramos en cuatro técnicas, todas ejecutables en
Ring 0:

| # | Técnica | Qué busca el atacante | Cómo se detecta |
|---|---------|-----------------------|-----------------|
| 1 | **SSDT Hooking** | Interceptar syscalls (p. ej. `NtCreateFile`) | Entradas de la SSDT que resuelven fuera de `nt` |
| 2 | **IDT Hooking** | Interceptar interrupciones (keylogger de teclado) | ISRs que apuntan a un módulo no confiable |
| 3 | **DKOM** | Ocultar procesos, conexiones o ficheros | Vista doble: lista enlazada vs. tabla de CID |
| 4 | **Red** | Ocultar/manipular conexiones y puertos | Hooks en las rutinas de dispatch de drivers de red |

> **Enfoque defensivo.** Todo el trabajo es de *análisis*: WinDbg y el script
> únicamente **leen** estructuras del kernel y comparan punteros. No se modifica
> el sistema en ningún momento.

---

## 2. Fundamentos: por qué importa el Ring 0

Windows separa la ejecución en **modo usuario** (Ring 3) y **modo kernel**
(Ring 0). El código que corre en Ring 0 —el núcleo, la *Executive*, la HAL y los
*drivers*— tiene acceso directo a la memoria física y a las estructuras internas
del sistema operativo, sin las restricciones del modo usuario.

Esto convierte al kernel en el objetivo ideal de los **rootkits**: un driver
malicioso cargado en Ring 0 puede modificar las propias estructuras que el
sistema usa para responder a consultas (qué procesos hay, qué interrupciones se
atienden, qué función gestiona cada syscall). Como el atacante manipula la
*fuente de la verdad*, las herramientas convencionales de modo usuario (Task
Manager, `netstat`, antivirus de Ring 3) dejan de ser fiables.

La forma robusta de detectar estas manipulaciones es **bajar al mismo nivel**:
inspeccionar las estructuras del kernel con un depurador de kernel (WinDbg) y
**verificar su integridad** contrastándolas con un punto de referencia que el
atacante no haya alterado (vista cruzada, rangos de módulos firmados, etc.).

---

## 3. Estructuras del kernel relevantes

Antes de detectar manipulaciones conviene recordar las estructuras que se van a
inspeccionar. Las consultaremos con el comando `dt` de WinDbg.

- **`_EPROCESS`** — representa un proceso. Campos clave para esta tarea:
  `UniqueProcessId` (PID), `ImageFileName` (nombre, `UCHAR[15]`) y
  `ActiveProcessLinks`, un `LIST_ENTRY` que enlaza todos los procesos activos.
- **`_LIST_ENTRY`** — nodo de lista doblemente enlazada con dos punteros:
  `Flink` (siguiente) y `Blink` (anterior). Es la base de `ActiveProcessLinks`.
- **`_DRIVER_OBJECT`** — imagen de un driver cargado. Campos clave: `DriverStart`
  (inicio de la imagen), `DriverSize` (tamaño) y `MajorFunction`, el vector de 28
  punteros a las rutinas de dispatch que atienden las solicitudes de E/S (IRPs).
- **`_KIDTENTRY64`** — entrada de la IDT (16 bytes en x64). La dirección de la
  ISR se reparte entre los campos `OffsetLow`, `OffsetMiddle` y `OffsetHigh`.
- **SSDT (`KiServiceTable`)** — tabla con las direcciones de las syscalls. En
  x64 **no almacena punteros**, sino **offsets relativos de 4 bytes** respecto a
  la propia base de la tabla.

> Muchas de estas estructuras son **opacas** (no documentadas oficialmente) y sus
> *offsets cambian entre versiones de Windows*. Por eso el script resuelve los
> offsets en tiempo de ejecución a partir de los símbolos del *target*, en lugar
> de codificarlos a mano.

---

## 4. Preparación del entorno de depuración

La detección requiere una sesión de **kernel debugging**. El esquema habitual y
recomendado es de **depuración remota** entre dos máquinas:

- **Máquina *debuggee*** (la analizada): una VM Windows x64 en la que se ejecuta
  el malware de prueba.
- **Máquina *debugger*** (la del analista): ejecuta WinDbg y se conecta a la VM.

Pasos resumidos:

1. En la VM *debuggee*, habilitar el modo de depuración del kernel:

   ```cmd
   bcdedit /debug on
   bcdedit /dbgsettings net hostip:w.x.y.z port:50000 key:1.2.3.4
   ```

   (Para depuración local en una sola máquina puede usarse *Local Kernel
   Debugging*, aunque no permite poner breakpoints ni controlar el flujo.)

2. En WinDbg (*debugger*), iniciar la sesión de kernel por red (*Kernel Debug →
   NET*) con el mismo puerto y *key*.

3. Configurar y cargar los **símbolos**, imprescindibles para resolver nombres de
   funciones y estructuras:

   ```
   .sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols
   .reload /f
   ```

> Sin símbolos del kernel, comandos como `x nt!KiServiceTable` o `dt nt!_EPROCESS`
> no funcionarán y el script abortará con un aviso.

---

## 5. Comandos de WinDbg para la detección

Subconjunto de comandos del módulo que usaremos a lo largo de la guía:

| Comando | Uso |
|---------|-----|
| `.reload /f` | Recargar símbolos |
| `lm` | Listar módulos cargados y sus rangos de memoria |
| `x nt!Sim*` | Localizar el offset/dirección de un símbolo |
| `!process 0 0` | Listar procesos vía `ActiveProcessLinks` |
| `dt nt!_EPROCESS <addr>` | Volcar una estructura y sus campos |
| `dps <addr>` | Mostrar punteros con su símbolo asociado |
| `dd` / `db` / `da` | Volcar memoria (dwords / bytes / ASCII) |
| `u <addr>` | Desensamblar en una dirección |
| `!idt -a` | Listar todas las entradas de la IDT y sus handlers |
| `!drvobj <name> 2` | Volcar el `DRIVER_OBJECT` y sus rutinas de dispatch |
| `dx <expr>` | Evaluar expresiones del modelo de datos (C++) |

La idea transversal de detección es siempre la misma: **tomar un puntero de
código (una syscall, una ISR, un dispatch) y comprobar si cae dentro del rango
`[inicio, fin]` de un módulo legítimo cargado** (`lm`). Si apunta a un módulo
inesperado —o a memoria que no pertenece a ningún módulo— es un fuerte indicio de
*hooking*.

---

## 6. Detección manual por técnica

### 6.1 SSDT Hooking

**Teoría.** La *System Service Descriptor Table* contiene las direcciones de las
rutinas del sistema (syscalls). Cuando un programa invoca una función del SO, el
kernel busca su dirección en la SSDT. Un rootkit que modifique una entrada puede
redirigir esa syscall a su propio código y controlar por completo el resultado
(por ejemplo, falsear el listado de ficheros desde `NtCreateFile`/`NtQueryDirectoryFile`).

**Detalle x64.** La tabla almacena offsets de 4 bytes; la dirección absoluta de
la rutina *i* se obtiene con:

```
rutina = KiServiceTable + (offset_con_signo_i >> 4)
```

**Detección manual.** Tomemos como ejemplo `NtCreateFile`, cuyo número de syscall
es `0x55`:

```
x nt!KiServiceTable                 ; base de la tabla
dd nt!KiServiceLimit L1             ; nº de syscalls
dx @$svc = (int*)&nt!KiServiceTable
dx (void*)((__int64)&nt!KiServiceTable + (@$svc[0x55] >> 4))
u  (__int64)&nt!KiServiceTable + (@$svc[0x55] >> 4)
```

La última instrucción debe desensamblar **dentro de `nt` (ntoskrnl)** y el
símbolo resuelto debe ser `nt!NtCreateFile`. **Indicador de compromiso:** la
dirección resuelta cae en otro módulo (un driver desconocido) o no pertenece a
ninguna imagen cargada.

![Resolución de una entrada de la SSDT]
<img width="886" height="487" alt="image" src="https://github.com/user-attachments/assets/79984398-5a96-4880-816c-60ab99460d5e" />


### 6.2 IDT Hooking (keylogger)

**Teoría.** La *Interrupt Descriptor Table* asocia cada interrupción con su
rutina de servicio (ISR). Modificando la entrada del **teclado** un rootkit puede
interceptar cada pulsación: es la base de un *keylogger* de kernel. La ISR
legítima del teclado PS/2 es `i8042prt!I8042KeyboardInterruptService`.

**Detección manual.**

```
!idt -a
```

Busca en la salida la línea de la interrupción de teclado y comprueba que su
handler apunta a `i8042prt` (o `kbdclass`). A nivel de estructura, puedes
reconstruir la entrada:

```
dx @$pcr->IdtBase                       ; base de la IDT del procesador actual
dt nt!_KIDTENTRY64 @$pcr->IdtBase       ; primera entrada (índice 0)
```

Cada entrada ocupa `0x10` bytes, de modo que la entrada del vector *N* está en
`IdtBase + N*0x10`. **Indicador de compromiso:** el handler del teclado apunta a
un driver distinto de `i8042prt`/`kbdclass`, o cualquier handler de la IDT cae
fuera de los módulos cargados.

> ⚠️ **Matiz fundamental en x64 (esto es lo que hace robusta la detección).** En
> Windows x64 la entrada de la IDT de una interrupción de dispositivo **no apunta
> directamente a la ISR del driver**: apunta a un *thunk* dentro de `nt`
> (`KiIsrThunk` / `KiInterruptDispatch`), y la ISR real se almacena en
> `KINTERRUPT.ServiceRoutine`. Por eso `!idt` muestra dos cosas distintas: la
> *dirección* de la entrada (un thunk en `nt`) y el *símbolo* de la ServiceRoutine
> que resuelve a través del objeto `KINTERRUPT` (p. ej. `i8042prt!...`). En el
> laboratorio se observa el vector `0x80` resolviendo a
> `i8042prt!I8042KeyboardInterruptService (KINTERRUPT ...)`: estado **limpio**. La
> consecuencia práctica es que comparar "módulo del símbolo" contra "módulo de la
> dirección" produce un falso positivo por cada interrupción de dispositivo; lo
> correcto es leer `nt!_KINTERRUPT.ServiceRoutine` y verificar **esa** dirección
> contra el mapa de módulos (es justo lo que hace el script, ver §9).

<img width="886" height="558" alt="image" src="https://github.com/user-attachments/assets/932f389c-d0e6-4492-ae91-a81b0032238f" />


### 6.3 DKOM: procesos ocultos

**Teoría.** *Direct Kernel Object Manipulation* manipula directamente objetos del
kernel en memoria. El caso clásico es **ocultar un proceso**: el rootkit recorre
la lista doblemente enlazada `ActiveProcessLinks`, localiza el `_EPROCESS` a
ocultar y hace que su nodo anterior y posterior se apunten entre sí (`Blink->Flink`
y `Flink->Blink`). El proceso **sigue ejecutándose** pero desaparece de cualquier
consulta basada en esa lista (`!process 0 0`, Task Manager…).

**Detección manual — vista cruzada.** Como la lista enlazada es justo lo que el
atacante altera, no podemos confiar en ella sola. Se compara con una **fuente
independiente** que el rootkit *no* ha tocado, típicamente la tabla de Client IDs
(`nt!PspCidTable`), que mapea PIDs a objetos:

```
!process 0 0                                  ; vista A (lista enlazada)
dt nt!_EPROCESS <addr> UniqueProcessId ImageFileName ActiveProcessLinks
```

Si un PID aparece en `PspCidTable` pero **no** en `!process 0 0`, ese proceso está
oculto por DKOM. También conviene verificar la **integridad** de la lista: para
todo nodo debe cumplirse `nodo->Flink->Blink == nodo`.

> **Verificación realizada en el laboratorio.** Volcando un `_EPROCESS` real
> (`brave.exe`, PID `0x718`) se observa su `ActiveProcessLinks.Flink` apuntando a
> `nt!PsActiveProcessHead` (ambas direcciones coinciden), lo que confirma que es el
> último nodo de la lista y que el enlazado circular está **íntegro**: no hay
> procesos desvinculados. Esta comprobación manual sustituye a la vista cruzada
> automática cuando la enumeración de `PspCidTable` no es concluyente en el build
> analizado (ver §9).

<img width="853" height="128" alt="image" src="https://github.com/user-attachments/assets/330ddd29-b759-453c-a92c-456903c95b36" />


### 6.4 Red: conexiones, puertos y dispatch hooks

**Teoría.** Para ocultar o manipular conexiones de red y puertos, un rootkit
puede aplicar DKOM sobre las estructuras de `tcpip.sys` o, de forma más general,
*hookear* las **rutinas de dispatch** (`DRIVER_OBJECT.MajorFunction`) de los
drivers que forman el stack de red (`tcpip`, `afd`, `netio`, `ndis`, `http`).

**Detección manual.**

```
!drvobj tcpip 2
dt nt!_DRIVER_OBJECT <addr> DriverStart DriverSize
```

Cada uno de los 28 punteros de `MajorFunction` debe apuntar a la **propia imagen
del driver**, a `nt` (`IopInvalidDeviceRequest`, el valor por defecto legítimo) o
a `fltmgr`. **Indicador de compromiso:** un puntero de dispatch que apunte a otro
módulo (o a memoria sin módulo) revela un *dispatch hook* que intercepta el
tráfico de E/S de red.

Para enumerar las conexiones activas, si la instalación dispone de la extensión
`!netstat`, úsala directamente; en caso contrario, la enumeración se hace
manualmente recorriendo las tablas de TCBs de `tcpip.sys` (sus offsets dependen
de la versión).

<img width="886" height="602" alt="image" src="https://github.com/user-attachments/assets/770b510e-f0d4-4948-8391-1b3caa65e3ce" />


---

## 7. Automatización con scripts

El módulo introduce tres vías para automatizar WinDbg:

1. **Scripts clásicos (`.wds`)** — comandos concatenados con `;`. Simples, pero
   sin variables ni estructuras de control reales, lo que limita la lógica.
2. **JavaScript** — motor integrado en WinDbg (`.scriptload` / `.scriptrun`); ya
   permite clases y lógica.
3. **PyKd** — *wrapper* entre WinDbg y Python. Es la opción **más idónea para
   scripts avanzados** por la flexibilidad del lenguaje y por poder resolver
   offsets y tipos dinámicamente.

Por ese motivo el script de esta entrega se ha desarrollado en **PyKd**: la
detección de SSDT/IDT/DKOM/red requiere leer estructuras, recorrer listas, hacer
aritmética de punteros y comparar contra rangos de módulos — tareas para las que
Python es claramente superior a un `.wds`.

---

## 8. El script `ring0_detector.py`

Automatiza, en una sola pasada, la detección manual de los cuatro apartados
anteriores. Solo **lee** memoria del kernel; no escribe nada.

### Carga y ejecución

En una sesión de kernel debugging ya conectada y con símbolos cargados:

```
0:kd> .load pykd.pyd
0:kd> !py C:\ruta\ring0_detector.py
```

O directamente sobre un volcado de memoria (modo *standalone*):

```cmd
python ring0_detector.py C:\ruta\MEMORY.DMP
```

### Qué hace cada módulo del script

- **`check_ssdt`** — recorre `KiServiceTable`, resuelve cada syscall con la
  fórmula x64 (`base + (offset >> 4)`) y marca toda entrada que **no** resuelva
  dentro de `nt`.
- **`check_idt`** — parsea `!idt -a` y, para cada vector, resuelve la **ISR real**
  leyendo `nt!_KINTERRUPT.ServiceRoutine` (no la dirección literal de la entrada,
  que en x64 es un *thunk* en `nt`). Avisa si la ISR real cae fuera de los módulos
  cargados o si el vector de teclado no apunta a `i8042prt`/`kbdclass` (posible
  keylogger).
- **`check_dkom`** — construye la **vista A** recorriendo `ActiveProcessLinks` y
  la **vista B** enumerando `PspCidTable`; cualquier PID solo presente en B es un
  proceso oculto. Verifica además la coherencia `Flink/Blink`. Si la vista B no
  devuelve procesos (o muchos menos que la A), declara el resultado **no
  concluyente** en lugar de un falso "limpio".
- **`check_network`** — para cada driver de red **valida primero que el objeto es
  un `_DRIVER_OBJECT` real** (`Type == 4`) antes de recorrer sus 28 rutinas
  `MajorFunction`, y comprueba que apuntan a destinos legítimos (la propia imagen,
  `nt!IopInvalidDeviceRequest` o `fltmgr`); intenta volcar conexiones con
  `!netstat` si está disponible.

La pieza común es `module_for_address()`, que sitúa cualquier puntero dentro del
mapa de módulos cargados — el corazón de toda la detección de *hooking*.

### Ejemplo de salida — qué se vería **con** un rootkit (ilustrativo)

```
==============================================================================
  1) SSDT Hooking  (KiServiceTable)
==============================================================================
  [ * ]  KiServiceTable = 0xfffff80312345000   (489 syscalls)
  [!!!]  Syscall #85 -> 0xfffff80abcd01230  módulo=evil  evil!Hook+0x30
  [!!!]  1 entrada(s) de la SSDT apuntan fuera de nt -> posible SSDT Hooking.

==============================================================================
  3) DKOM  (procesos ocultos)
==============================================================================
  [ * ]  Procesos en la lista enlazada (ActiveProcessLinks): 73
  [ * ]  Procesos vistos vía PspCidTable (vista independiente): 74
  [!!!]  PROCESO OCULTO  PID=4920  EPROCESS=0xffff958f6271b080  nombre=evil.exe  -> DKOM
```

### Salida real sobre la línea base limpia (laboratorio)

Ejecución sobre la VM analizada (sana, sin rootkit). Las tres comprobaciones de
*hooking* dan `[OK]` y DKOM informa honestamente de que la vista independiente no
es concluyente en este build:

```
  1) SSDT Hooking   -> [OK]  Todas las entradas resuelven dentro de nt. Sin hooks.
  2) IDT Hooking    -> [OK]  Todas las ISR (resueltas vía KINTERRUPT) en módulos cargados.
  3) DKOM           -> [?]   Lista enlazada: 154 procesos. Vista independiente NO concluyente.
  4) Red            -> [OK]  Dispatch de tcpip/afd/ndis/http intacto. Sin hooks.
```

<img width="886" height="335" alt="image" src="https://github.com/user-attachments/assets/ac1ae09e-74de-4b7e-9abf-fbc9d65acd84" />


