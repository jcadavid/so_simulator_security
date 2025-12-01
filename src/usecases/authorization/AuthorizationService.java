package usecases.authorization;

import entities.AccessControlMatrix;
import entities.Resource;
import entities.audit.AuditEvent;
import entities.audit.AuditLog;
import entities.permissons.Permission;
import entities.permissons.SecurityLevel;
import entities.user.User;

import java.util.EnumSet;

public class AuthorizationService {

    private final AccessControlMatrix accessControlMatrix;
    private final AuditLog auditLog;

    public AuthorizationService(AccessControlMatrix accessControlMatrix, AuditLog auditLog) {
        this.accessControlMatrix = accessControlMatrix;
        this.auditLog = auditLog;
    }

    /**
     * Verifica si un usuario puede ejercer un permiso sobre un recurso.
     * La decisión combina:
     * - Seguridad obligatoria (Bell-LaPadula) basada en niveles.
     * - Seguridad discrecional (DAC) usando:
     * * la matriz de control de acceso (usuario-recurso),
     * * los permisos del recurso (owner / others).
     */
    public boolean checkAccess(User user, Resource resource, Permission permission) {
        // 1. Verificar seguridad obligatoria (MAC / Bell-LaPadula)
        if (!checkBellLaPadula(user, resource, permission)) {
            auditLog.record(new AuditEvent(
                    user.name(),
                    resource.getName(),
                    permission.name(),
                    false,
                    "Acceso denegado por política Bell-LaPadula (MAC)"
            ));
            return false;
        }

        // 2. Calcular permisos efectivos (DAC: matriz + permisos del recurso)
        EnumSet<Permission> effectivePermissions = computeEffectivePermissions(user, resource);

        boolean allowed = effectivePermissions.contains(permission);

        auditLog.record(new AuditEvent(
                user.name(),
                resource.getName(),
                permission.name(),
                allowed,
                allowed
                        ? "Acceso permitido (DAC: matriz + permisos del recurso)"
                        : "Acceso denegado (DAC: matriz + permisos del recurso)"
        ));

        return allowed;
    }

    /**
     * Combina permisos de:
     * - matriz de control de acceso (AccessControlMatrix)
     * - permisos del recurso (ownerPermissions / othersPermissions).
     */
    private EnumSet<Permission> computeEffectivePermissions(User user, Resource resource) {
        EnumSet<Permission> effective = EnumSet.noneOf(Permission.class);

        // 2.1 Permisos provenientes de la matriz de control de acceso
        EnumSet<Permission> matrixPerms =
                accessControlMatrix.getPermissions(user.name(), resource.getName());
        if (matrixPerms != null) {
            effective.addAll(matrixPerms);
        }

        // 2.2 Permisos provenientes del propio recurso (tipo UNIX/ACL embebida)
        if (resource.getOwner().equals(user) && resource.getOwnerPermissions() != null) {
            // Es el propietario del recurso
            effective.addAll(resource.getOwnerPermissions());
        } else if (resource.getOthersPermissions() != null) {
            effective.addAll(resource.getOthersPermissions());
        }

        return effective;
    }

    /**
     * Implementación simplificada de Bell-LaPadula:
     * - No read up: un sujeto no puede leer información de nivel superior.
     * - No write down: un sujeto no puede escribir en información de nivel inferior.
     */
    private boolean checkBellLaPadula(User user, Resource resource, Permission permission) {
        SecurityLevel userLevel = user.level();
        SecurityLevel resourceLevel = resource.getLevel();

        // Clasificamos permisos en "lectura" y "escritura"
        EnumSet<Permission> readLike = EnumSet.of(
                Permission.READ,
                Permission.PRINT,
                Permission.EXECUTE
        );

        EnumSet<Permission> writeLike = EnumSet.of(
                Permission.WRITE,
                Permission.DELETE,
                Permission.CONFIGURE
        );

        // No read up: no se puede LEER hacia arriba
        if (readLike.contains(permission)) {
            // Para poder leer, el nivel del usuario debe ser >= que el del recurso
            return userLevel.ordinal() >= resourceLevel.ordinal();
        }

        // No write down: no se puede ESCRIBIR hacia abajo
        if (writeLike.contains(permission)) {
            // Para poder escribir, el nivel del usuario debe ser <= que el del recurso
            return userLevel.ordinal() <= resourceLevel.ordinal();
        }

        // Para otros permisos no clasificados, no aplicamos restricciones MAC adicionales
        return true;
    }

    /**
     * Simula un intento de modificación de permisos sobre un recurso.
     * Si el usuario no es administrador ni propietario, se considera un intento de escalada.
     */
    public void tryModifyPermissions(User actor, Resource resource, User targetUser) {
        boolean isAdmin = actor.admin();
        boolean isOwner = resource.getOwner().equals(actor);
        boolean allowedToChange = isAdmin || isOwner;

        if (!allowedToChange) {
            auditLog.record(new AuditEvent(
                    actor.name(),
                    resource.getName(),
                    "MODIFY_PERMISSIONS",
                    false,
                    "Intento de escalada de privilegios al modificar permisos de un recurso"
            ));
            return;
        }

        // Ejemplo simple: el actor otorga permiso de escritura al usuario objetivo
        EnumSet<Permission> current =
                accessControlMatrix.getPermissions(targetUser.name(), resource.getName());
        EnumSet<Permission> newPerms = (current != null)
                ? EnumSet.copyOf(current)
                : EnumSet.noneOf(Permission.class);

        newPerms.add(Permission.WRITE);
        accessControlMatrix.grant(targetUser.name(), resource.getName(), newPerms);

        auditLog.record(new AuditEvent(
                actor.name(),
                resource.getName(),
                "MODIFY_PERMISSIONS",
                true,
                "Permisos actualizados para usuario " + targetUser.name()
        ));
    }
}
