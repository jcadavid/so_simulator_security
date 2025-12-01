package usecases.rootkit;

import entities.AccessControlMatrix;
import entities.permissons.Permission;

import java.util.EnumSet;

public class RootkitSimulator {

    private final AccessControlMatrix matrix;

    public RootkitSimulator(AccessControlMatrix matrix) {
        this.matrix = matrix;
    }

    /**
     * Simular un rootkit que silenciosamente asigna permisos a un usuario
     * sobre un recurso, saltándose todos los sistemas planteados
     */
    public void silentlyEscalate(String userName, String resourceName) {
        EnumSet<Permission> elevated = EnumSet.allOf(Permission.class);
        // Directamente, escribe sobre la matriz, aquí se puede observar que no hay auditoria.
        matrix.grant(userName, resourceName, elevated);
    }
}
