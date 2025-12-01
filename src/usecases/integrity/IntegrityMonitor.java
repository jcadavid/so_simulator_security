package usecases.integrity;

import entities.AccessControlMatrix;
import entities.audit.AuditEvent;
import entities.audit.AuditLog;
import entities.permissons.Permission;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class IntegrityMonitor {

    private final AccessControlMatrix matrix;
    private final AuditLog auditLog;

    // Captura del estado actual de la matriz
    private Map<String, Map<String, EnumSet<Permission>>> baselineSnapshot = null;

    public IntegrityMonitor(AccessControlMatrix matrix, AuditLog auditLog) {
        this.matrix = matrix;
        this.auditLog = auditLog;
    }

    /**
     * Toma una captura del estado actual de la matriz
     * esto representaría el estado confiable.
     */
    public void takeBaseline() {
        baselineSnapshot = matrix.exportMatrixSnapshot();
        auditLog.record(new AuditEvent(
                "INTEGRITY_MODULE",
                "-",
                "BASELINE_TAKEN",
                true,
                "Baseline de integridad tomada sobre la matriz de control de acceso."
        ));
    }

    /**
     * Compara la matriz actual con la matriz anterior guardad
     * y almacena cada diferencia para reportar si hubo una modificación
     */
    public void checkIntegrity() {
        if (baselineSnapshot == null) {
            auditLog.record(new AuditEvent(
                    "INTEGRITY_MODULE",
                    "-",
                    "INTEGRITY_CHECK",
                    false,
                    "No hay baseline de integridad previa. Primero debe tomarse una baseline."
            ));
            System.out.println("No hay baseline de integridad. Use la opción de menú para tomarla primero.");
            return;
        }

        Map<String, Map<String, EnumSet<Permission>>> current = matrix.exportMatrixSnapshot();
        boolean changesDetected = false;

        // Conjunto de todos los usuarios que aparecen en baseline o en current
        Set<String> allUsers = new HashSet<>();
        allUsers.addAll(baselineSnapshot.keySet());
        allUsers.addAll(current.keySet());

        for (String user : allUsers) {
            Map<String, EnumSet<Permission>> baseRes =
                    baselineSnapshot.getOrDefault(user, Map.of());
            Map<String, EnumSet<Permission>> currRes =
                    current.getOrDefault(user, Map.of());

            // Conjunto de todos los recursos que aparecen en baseline o en current para este usuario
            Set<String> allResources = new HashSet<>();
            allResources.addAll(baseRes.keySet());
            allResources.addAll(currRes.keySet());

            for (String resourceName : allResources) {
                EnumSet<Permission> basePerms =
                        baseRes.getOrDefault(resourceName, EnumSet.noneOf(Permission.class));
                EnumSet<Permission> currPerms =
                        currRes.getOrDefault(resourceName, EnumSet.noneOf(Permission.class));

                if (!basePerms.equals(currPerms)) {
                    changesDetected = true;
                    String detail = String.format(
                            "Cambio de integridad detectado para user=%s, resource=%s. Antes=%s, Ahora=%s",
                            user, resourceName, basePerms, currPerms
                    );

                    auditLog.record(new AuditEvent(
                            "INTEGRITY_MODULE",
                            resourceName,
                            "INTEGRITY_ALERT",
                            false,
                            detail
                    ));
                }
            }
        }

        if (!changesDetected) {
            auditLog.record(new AuditEvent(
                    "INTEGRITY_MODULE",
                    "-",
                    "INTEGRITY_CHECK",
                    true,
                    "No se detectaron cambios en la matriz respecto a la baseline."
            ));
            System.out.println("Integridad OK: no se detectaron cambios respecto a la baseline.");
        } else {
            System.out.println("¡ALERTA! Se detectaron cambios en la matriz de control de acceso respecto a la baseline.");
            System.out.println("Consulte el registro de auditoría para más detalles.");
        }
    }
}

