package entities;

import entities.permissons.Permission;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

public class AccessControlMatrix {

    private final Map<String, Map<String, EnumSet<Permission>>> matrix = new HashMap<>();

    public void grant(String userName, String resourceName, EnumSet<Permission> permissions) {
        matrix.computeIfAbsent(userName, u -> new HashMap<>())
                .put(resourceName, permissions);
    }

    public EnumSet<Permission> getPermissions(String userName, String resourceName) {
        return matrix.getOrDefault(userName, Collections.emptyMap())
                .getOrDefault(resourceName, EnumSet.noneOf(Permission.class));
    }

    /**
     * Devuelve una copia completa de la actual matriz de acceso
     * Usada por el monitor de integridad.
     */
    public Map<String, Map<String, EnumSet<Permission>>> exportMatrixSnapshot() {
        Map<String, Map<String, EnumSet<Permission>>> copy = new HashMap<>();

        for (var userEntry : matrix.entrySet()) {
            String user = userEntry.getKey();
            Map<String, EnumSet<Permission>> inner = new HashMap<>();

            for (var resEntry : userEntry.getValue().entrySet()) {
                String resourceName = resEntry.getKey();
                EnumSet<Permission> permsCopy = EnumSet.copyOf(resEntry.getValue());
                inner.put(resourceName, permsCopy);
            }
            copy.put(user, inner);
        }
        return copy;
    }

}
