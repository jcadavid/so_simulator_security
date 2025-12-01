import entities.AccessControlMatrix;
import entities.Resource;
import entities.audit.AuditLog;
import entities.permissons.Permission;
import entities.permissons.SecurityLevel;
import entities.user.User;
import usecases.authentication.AuthenticationService;
import usecases.authorization.AuthorizationService;
import usecases.integrity.IntegrityMonitor;
import usecases.rootkit.RootkitSimulator;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class SecuritySimulator {

    private final AuditLog auditLog;
    private final Map<String, User> users;
    private final Map<String, Resource> resources;
    private final AccessControlMatrix matrix;
    private final AuthenticationService authenticationService;
    private final AuthorizationService authorizationService;
    private final RootkitSimulator rootkitSimulator;
    private final IntegrityMonitor integrityMonitor;
    private final Scanner scanner;

    public SecuritySimulator() {
        this.auditLog = new AuditLog();
        this.users = new HashMap<>();
        this.resources = new HashMap<>();
        this.matrix = new AccessControlMatrix();
        this.authenticationService = new AuthenticationService(users, auditLog);
        this.authorizationService = new AuthorizationService(matrix, auditLog);
        this.rootkitSimulator = new RootkitSimulator(matrix);
        this.integrityMonitor = new IntegrityMonitor(matrix, auditLog);
        this.scanner = new Scanner(System.in);
    }

    public static void main(String[] args) {
        SecuritySimulator simulator = new SecuritySimulator();
        // Inicializamos un escenario por defecto con usuarios, recursos y matriz
        simulator.initializeDefaultScenario();
        simulator.runInteractiveMenu();
    }

    /**
     * Inicializa el escenario por defecto:
     * usuarios: alice, bob, admin
     * recursos: report.pdf, system_config.conf
     * y permisos básicos en la matriz de control de acceso.
     */
    private void initializeDefaultScenario() {
        // Crear usuarios por defecto
        final User alice = new User("alice", "alice123", false, SecurityLevel.CONFIDENTIAL);
        final User bob = new User("bob", "bob123", false, SecurityLevel.PUBLIC);
        final User admin = new User("admin", "admin123", true, SecurityLevel.SECRET);

        users.put(alice.name(), alice);
        users.put(bob.name(), bob);
        users.put(admin.name(), admin);

        // Crear recursos por defecto
        final Resource report = new Resource("report.pdf", alice, SecurityLevel.CONFIDENTIAL, false);
        final Resource systemConfig = new Resource("system_config.conf", admin, SecurityLevel.SECRET, true);

        // Permisos tipo UNIX simplificados
        report.setOwnerPermissions(EnumSet.of(Permission.READ, Permission.WRITE));
        report.setOthersPermissions(EnumSet.of(Permission.READ));

        systemConfig.setOwnerPermissions(EnumSet.of(Permission.READ, Permission.WRITE, Permission.DELETE));
        systemConfig.setOthersPermissions(EnumSet.noneOf(Permission.class));

        resources.put(report.getName(), report);
        resources.put(systemConfig.getName(), systemConfig);

        // Configurar la matriz de control de acceso por defecto
        matrix.grant("alice", "report.pdf", EnumSet.of(Permission.READ, Permission.WRITE));
        matrix.grant("bob", "report.pdf", EnumSet.of(Permission.READ));
        matrix.grant("admin", "report.pdf",
                EnumSet.of(Permission.READ, Permission.WRITE, Permission.DELETE));

        matrix.grant("admin", "system_config.conf",
                EnumSet.of(Permission.READ, Permission.WRITE, Permission.DELETE, Permission.CONFIGURE));

        integrityMonitor.takeBaseline();
    }

    /**
     * Ejecuta el escenario de demostración por defecto
     * utilizando los usuarios, recursos y matriz actuales.
     */
    private void runDefaultDemo() {
        System.out.println("Ejecutando demostración por defecto...");

        // Si por alguna razón el escenario por defecto no existe, lo inicializamos
        if (!users.containsKey("alice") || !resources.containsKey("report.pdf")) {
            System.out.println("Escenario por defecto no inicializado. Inicializando ahora...");
            initializeDefaultScenario();
        }

        // Autenticación
        final User uAlice = authenticationService.authenticate("alice", "alice123");
        final User uBob = authenticationService.authenticate("bob", "bob123");
        final User uAdmin = authenticationService.authenticate("admin", "admin123");

        final Resource report = resources.get("report.pdf");
        final Resource systemConfig = resources.get("system_config.conf");

        // Verificación de accesos (matriz + Bell-LaPadula)
        if (uAlice != null && report != null && systemConfig != null) {
            authorizationService.checkAccess(uAlice, report, Permission.READ);       // debería permitir
            authorizationService.checkAccess(uAlice, systemConfig, Permission.READ); // debería denegar (nivel)
        }

        if (uBob != null && report != null) {
            authorizationService.checkAccess(uBob, report, Permission.WRITE);        // debería denegar
        }

        if (uAdmin != null && systemConfig != null) {
            authorizationService.checkAccess(uAdmin, systemConfig, Permission.CONFIGURE); // debería permitir
        }

        // Simulación de intento de escalada de privilegios
        if (uBob != null && systemConfig != null) {
            authorizationService.tryModifyPermissions(uBob, systemConfig, users.get("alice"));
        }

        System.out.println("Demostración por defecto finalizada. Registro de auditoría hasta el momento:");
        auditLog.print();

        // Tomar baseline de integridad después de la demo (puede sobreescribir la anterior)
        integrityMonitor.takeBaseline();
    }

    /**
     * Bucle principal interactivo con un menú en consola.
     */
    private void runInteractiveMenu() {
        boolean exit = false;

        while (!exit) {
            printMenu();
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1" -> addUserInteractive();
                case "2" -> addResourceInteractive();
                case "3" -> grantPermissionInteractive();
                case "4" -> authenticateAndCheckAccessInteractive();
                case "5" -> runDefaultDemo();
                case "6" -> auditLog.print();
                case "7" -> simulateRootkitInteractive();
                case "8" -> takeBaselineInteractive();
                case "9" -> checkIntegrityInteractive();
                case "0" -> {
                    System.out.println("Saliendo del simulador...");
                    exit = true;
                }
                default -> System.out.println("Opción inválida. Intente de nuevo.");
            }
        }
    }

    /**
     * Imprime el menú principal del simulador.
     */
    private void printMenu() {
        System.out.println("\n=== MENÚ DEL SIMULADOR DE SEGURIDAD ===");
        System.out.println("1. Agregar usuario");
        System.out.println("2. Agregar recurso");
        System.out.println("3. Otorgar permisos (Matriz de Control de Acceso)");
        System.out.println("4. Autenticar usuario y verificar acceso");
        System.out.println("5. Ejecutar demostración por defecto");
        System.out.println("6. Mostrar registro de auditoría");
        System.out.println("7. Simular rootkit (escalada de privilegios dentro del simulador)");
        System.out.println("8. Tomar baseline de integridad");
        System.out.println("9. Verificar integridad de la matriz");
        System.out.println("0. Salir");
        System.out.print("Seleccione una opción: ");
    }

    // === Acciones del menú ===

    /**
     * Agrega un nuevo usuario al sistema de forma interactiva.
     */
    private void addUserInteractive() {
        System.out.println("\n-- Agregar usuario --");

        System.out.print("Nombre del usuario: ");
        final String name = scanner.nextLine().trim();
        if (users.containsKey(name)) {
            System.out.println("El usuario ya existe.");
            return;
        }

        System.out.print("Contraseña: ");
        final String password = scanner.nextLine().trim();

        System.out.print("¿Es administrador? (s/n): ");
        final String adminInput = scanner.nextLine().trim().toLowerCase();
        boolean isAdmin = adminInput.startsWith("s");

        System.out.println("Niveles de seguridad disponibles: PUBLICO, CONFIDENCIAL, SECRETO");
        System.out.print("Nivel de seguridad: ");
        final String levelInput = scanner.nextLine().trim().toUpperCase();

        SecurityLevel level;
        try {
            level = SecurityLevel.valueOf(levelInput);
        } catch (IllegalArgumentException e) {
            System.out.println("Nivel inválido. Se asignará PUBLICO.");
            level = SecurityLevel.PUBLIC;
        }

        final User user = new User(name, password, isAdmin, level);
        users.put(name, user);
        System.out.println("Usuario creado: " + name);
    }

    /**
     * Agrega un nuevo recurso al sistema de forma interactiva.
     */
    private void addResourceInteractive() {
        System.out.println("\n-- Agregar recurso --");

        System.out.print("Nombre del recurso: ");
        final String resourceName = scanner.nextLine().trim();
        if (resources.containsKey(resourceName)) {
            System.out.println("El recurso ya existe.");
            return;
        }

        System.out.print("Nombre del usuario propietario: ");
        final String ownerName = scanner.nextLine().trim();
        final User owner = users.get(ownerName);
        if (owner == null) {
            System.out.println("El usuario propietario no existe.");
            return;
        }

        System.out.println("Niveles disponibles: PUBLICO, CONFIDENCIAL, SECRETO");
        System.out.print("Nivel de seguridad: ");
        final String levelInput = scanner.nextLine().trim().toUpperCase();

        SecurityLevel level;
        try {
            level = SecurityLevel.valueOf(levelInput);
        } catch (IllegalArgumentException e) {
            System.out.println("Nivel inválido. Se asignará PUBLICO.");
            level = SecurityLevel.PUBLIC;
        }

        System.out.print("¿Es un recurso crítico? (s/n): ");
        final String criticalInput = scanner.nextLine().trim().toLowerCase();
        final boolean critical = criticalInput.startsWith("s");

        final Resource resource = new Resource(resourceName, owner, level, critical);

        // Por defecto, el propietario tiene READ y WRITE, otros no tienen permisos
        resource.setOwnerPermissions(EnumSet.of(Permission.READ, Permission.WRITE));
        resource.setOthersPermissions(EnumSet.noneOf(Permission.class));

        resources.put(resourceName, resource);
        System.out.println("Recurso creado: " + resourceName);
    }

    /**
     * Otorga permisos a un usuario sobre un recurso dentro de la matriz de control de acceso.
     */
    private void grantPermissionInteractive() {
        System.out.println("\n-- Otorgar permisos a un usuario sobre un recurso --");

        System.out.print("Nombre del usuario: ");
        final String userName = scanner.nextLine().trim();
        if (!users.containsKey(userName)) {
            System.out.println("Ese usuario no existe.");
            return;
        }

        System.out.print("Nombre del recurso: ");
        final String resourceName = scanner.nextLine().trim();
        if (!resources.containsKey(resourceName)) {
            System.out.println("Ese recurso no existe.");
            return;
        }

        System.out.println("Permisos disponibles: READ, WRITE, EXECUTE, PRINT, CONFIGURE, DELETE");
        System.out.print("Ingrese los permisos (separados por coma, ejemplo: READ,WRITE): ");
        final String permsInput = scanner.nextLine().trim();

        final EnumSet<Permission> perms = EnumSet.noneOf(Permission.class);
        if (!permsInput.isEmpty()) {
            final String[] parts = permsInput.split(",");
            for (String p : parts) {
                try {
                    perms.add(Permission.valueOf(p.trim().toUpperCase()));
                } catch (IllegalArgumentException e) {
                    System.out.println("Permiso inválido ignorado: " + p);
                }
            }
        }

        matrix.grant(userName, resourceName, perms);
        integrityMonitor.takeBaseline();
        System.out.println("Permisos otorgados correctamente.");
    }

    /**
     * Autentica un usuario y verifica si tiene acceso a un recurso con un permiso específico.
     */
    private void authenticateAndCheckAccessInteractive() {
        System.out.println("\n-- Autenticar usuario y verificar acceso --");

        System.out.print("Nombre del usuario: ");
        final String userName = scanner.nextLine().trim();
        System.out.print("Contraseña: ");
        final String password = scanner.nextLine().trim();

        final User user = authenticationService.authenticate(userName, password);
        if (user == null) {
            System.out.println("Autenticación fallida.");
            return;
        }

        System.out.print("Nombre del recurso: ");
        final String resourceName = scanner.nextLine().trim();
        final Resource resource = resources.get(resourceName);
        if (resource == null) {
            System.out.println("El recurso no existe.");
            return;
        }

        System.out.println("Permisos disponibles: READ, WRITE, EXECUTE, PRINT, CONFIGURE, DELETE");
        System.out.print("Permiso a verificar: ");
        String permInput = scanner.nextLine().trim().toUpperCase();

        Permission permission;
        try {
            permission = Permission.valueOf(permInput);
        } catch (IllegalArgumentException e) {
            System.out.println("Permiso inválido.");
            return;
        }

        final boolean allowed = authorizationService.checkAccess(user, resource, permission);
        System.out.println("Resultado del acceso: " + (allowed ? "PERMITIDO" : "DENEGADO"));
    }

    /**
     * Simula un rootkit que modifica la matriz de control de acceso de forma silenciosa.
     */
    private void simulateRootkitInteractive() {
        System.out.println("\n-- Simulación de rootkit (solo dentro del simulador) --");
        System.out.println("Esta simulación NO afecta al sistema operativo real.");
        System.out.print("Nombre del usuario víctima: ");
        final String userName = scanner.nextLine().trim();

        if (!users.containsKey(userName)) {
            System.out.println("El usuario no existe.");
            return;
        }

        System.out.print("Nombre del recurso objetivo: ");
        final String resourceName = scanner.nextLine().trim();

        if (!resources.containsKey(resourceName)) {
            System.out.println("El recurso no existe.");
            return;
        }

        // Permisos antes
        final var before = matrix.getPermissions(userName, resourceName);
        System.out.println("Permisos ANTES de la simulación de rootkit: " + before);

        // Rootkit modifica la matriz en silencio (sin registrar en el log)
        rootkitSimulator.silentlyEscalate(userName, resourceName);

        // Permisos después
        final var after = matrix.getPermissions(userName, resourceName);
        System.out.println("Permisos DESPUÉS de la simulación de rootkit: " + after);

        System.out.println("Ahora puede intentar autenticar al usuario y verificar acceso (opción 4)");
        System.out.println("para ver cómo el sistema 'cree' que esos permisos son legítimos.");
    }

    /**
     * Toma una baseline de integridad de la matriz de control de acceso.
     */
    private void takeBaselineInteractive() {
        System.out.println("\n-- Tomar baseline de integridad --");
        integrityMonitor.takeBaseline();
        System.out.println("Baseline de integridad tomada. A partir de ahora se compararán los cambios contra este estado.");
    }

    /**
     * Verifica la integridad de la matriz de control de acceso comparando con la baseline previa.
     */
    private void checkIntegrityInteractive() {
        System.out.println("\n-- Verificar integridad de la matriz de control de acceso --");
        integrityMonitor.checkIntegrity();
    }
}
