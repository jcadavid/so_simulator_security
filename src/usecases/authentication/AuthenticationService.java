package usecases.authentication;

import entities.audit.AuditEvent;
import entities.audit.AuditLog;
import entities.user.User;

import java.util.Map;

public class AuthenticationService {

    private final Map<String, User> users;
    private final AuditLog auditLog;

    public AuthenticationService(Map<String, User> users, AuditLog auditLog) {
        this.users = users;
        this.auditLog = auditLog;
    }

    /**
     * Verifica si un usuario se puede autenticar.
     * @param name nombre de usuario.
     * @param password contraseña.
     * @return
     */
    public User authenticate(String name, String password) {
        User user = users.get(name);
        boolean success = (user != null && user.password().equals(password));

        auditLog.record(new AuditEvent(
                name,
                "-",
                "LOGIN",
                success,
                success ? "Inicio sesión exitoso" : "Inicio de sesión fallido"
        ));

        return success ? user : null;
    }
}
