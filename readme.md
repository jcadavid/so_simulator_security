# Momento Evaluativo – Tema 3: Seguridad de Sistemas Operativos
# Descripción General

Este proyecto implementa un simulador educativo que reproduce los principales mecanismos de seguridad utilizados por un sistema operativo moderno (Windows, Linux, macOS):

- Autenticación
- Autorización
- Auditoría
- Permisos y controles de acceso
- Modelo Bell-LaPadula
- Escalada de privilegios
- Rootkits simulados
- Verificación de integridad

Todo ocurre dentro del programa, sin modificar en ningún momento el sistema operativo real.
Es completamente seguro de ejecutar.

Este simulador sirve como apoyo conceptual y práctico para el Momento Evaluativo – Tema 3: Seguridad de Sistemas Operativos.

# Objetivos del Proyecto

- Comprender y visualizar cómo un SO protege sus recursos internos.
- Explorar cómo se implementan los controles de acceso (DAC y MAC).
- Mostrar cómo se detectan cambios ilegítimos mediante un módulo de integridad.
- Simular cómo actúa un rootkit modificando estructuras internas sin dejar rastro.
- Permitir que cualquier usuario pruebe el funcionamiento mediante un menú interactivo.

## Ejecución Rápida
### Requisitos

Java 17 o superior

#### Verificar versión:

`java -version`

**Compilación**
`javac SecuritySimulator.java`

#### Ejecución
`java SecuritySimulator`

## Menú principal del simulador

```
=== MENÚ DEL SIMULADOR DE SEGURIDAD ===
1. Agregar usuario
2. Agregar recurso
3. Otorgar permisos (Matriz de Control de Acceso)
4. Autenticar usuario y verificar acceso
5. Ejecutar demostración por defecto
6. Mostrar registro de auditoría
7. Simular rootkit (escalada silenciosa)
8. Tomar baseline de integridad
9. Verificar integridad
0. Salir
```

### ¿Qué conceptos del Momento Evaluativo se están simulando?

El simulador implementa de manera fiel los mecanismos enseñados en el Tema 3 – Seguridad de Sistemas Operativos:

| Concepto del curso                 | Implementación                        |
| ---------------------------------- | ------------------------------------- |
| Protección                         | Permisos, matriz de control, dominios |
| Seguridad                          | Autenticación, auditoría, integridad  |
| Matriz de Control de Acceso (ACM)  | `AccessControlMatrix`                 |
| ACLs                               | Permisos por recurso                  |
| Dominios de protección             | Lógica central de autorización        |
| Autenticación                      | `AuthenticationService`               |
| Autorización                       | `AuthorizationService`                |
| Auditoría                          | `AuditLog`, `AuditEvent`              |
| Modelo Bell-LaPadula               | Niveles de seguridad y reglas MAC     |
| DAC (Discretionary Access Control) | Permisos asignados por administrador  |
| MAC (Mandatory Access Control)     | Bell-LaPadula                         |
| Escalada de privilegios            | `tryModifyPermissions`                |
| Rootkits                           | `RootkitSimulator.silentlyEscalate()` |
| Verificación de integridad         | `IntegrityMonitor`                    |
| Recursos críticos                  | Marcados en `Resource`                |

### Creación de usuarios, recursos y permisos

El simulador permite crear usuarios con contraseña, rol (administrador o no) y nivel de seguridad (Público, Confidencial o Secreto). También permite crear recursos con propietario, nivel de sensibilidad y criticidad.
La relación usuario–recurso se gestiona mediante una Matriz de Control de Acceso, donde se asignan permisos específicos como READ, WRITE o CONFIGURE. Esto replica los mecanismos de Control de Acceso Discrecional (DAC), las ACLs y el concepto de dominios de protección usados en sistemas operativos.

### Autenticación

Antes de acceder a un recurso, el usuario debe autenticarse mediante nombre y contraseña. Si los datos coinciden, el sistema valida la identidad y habilita a ese usuario para solicitar permisos.
Este proceso emula la autenticación básica de sistemas operativos reales (login en Linux, Windows o macOS) dentro del modelo AAA, en su fase “¿quién eres?”.

### Auditoría

Cada intento de acceso, autenticación, concesión de permisos o evento relevante se registra en un log interno. Este registro permite visualizar qué acciones se realizaron y si fueron permitidas o denegadas.
Esto reproduce los mecanismos de auditoría de seguridad presentes en Windows Event Log, Linux auditd o el sistema de logging de macOS, cuya función principal es la trazabilidad y el análisis posterior de incidentes.

### Rootkit

El simulador incluye un módulo que modifica la matriz de acceso sin usar los mecanismos de autorización y sin generar registros de auditoría. El usuario afectado adquiere permisos adicionales sin que el sistema lo note, salvo por la verificación de integridad.
Este componente modela el comportamiento real de un rootkit, que altera estructuras internas del sistema operativo, evade registros y permite escalada de privilegios silenciosa.

### Integridad

El usuario puede capturar una “baseline” o estado confiable de los permisos. Luego, el sistema compara la matriz actual con esa baseline para verificar si ha sido alterada sin autorización.
Este proceso reproduce la función de herramientas de verificación de integridad (como Tripwire o AIDE) y los módulos HIDS que detectan manipulación interna, especialmente ante amenazas como rootkits o modificaciones ilegítimas de permisos.

## El proyecto se organiza en dos grandes áreas:

- Entities (núcleo del modelo)
  - User
  - Resource
  - Permission
  - SecurityLevel
  - AccessControlMatrix
  - AuditLog 
  - AuditEvent

- UseCases (lógica de seguridad)
  - AuthenticationService
  - AuthorizationService
  - RootkitSimulator
  - IntegrityMonitor

- Interfaz del usuario
  - SecuritySimulator (menú interactivo + casos)



## Guía rápida para probar el simulador
### Ejecutar la demostración

Selecciona:
### 5. Ejecutar demostración por defecto

Esto muestra:
- Accesos permitidos
- Accesos denegados
- Auditoría
- Escalada detectada

### Crear un usuario

```
1. Agregar usuario
   Nombre: juan
   Contraseña: 1234
   Admin: n
   Nivel: PUBLICO
```

### Crear un recurso

```
2. Agregar recurso
   Nombre: datos.txt
   Propietario: juan
   Nivel: CONFIDENCIAL
   Crítico: n
```

### Otorgar permisos

```
3. Otorgar permisos
   Usuario: juan
   Recurso: datos.txt
   Permisos: READ,WRITE
```

### Probar acceso

```
4. Autenticar usuario y verificar acceso
   Usuario: juan
   Contraseña: 1234
   Recurso: datos.txt
   Permiso: WRITE
```

### Simular un rootkit

```
7. Simular rootkit
   Usuario víctima: juan
   Recurso objetivo: datos.txt
```

**El rootkit modifica la matriz sin dejar rastro.**

### Detectar el rootkit

Primero:

`8. Tomar baseline de integridad`

Luego:

`9. Verificar integridad`

El sistema detectará el cambio:

`¡ALERTA! Se detectaron cambios en la matriz de control de acceso...`
