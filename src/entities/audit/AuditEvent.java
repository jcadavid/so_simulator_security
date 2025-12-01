package entities.audit;

import java.util.Date;

/**
 * Entidad para guardar los eventos de auditoria
 */
public class AuditEvent {

    private final Date timestamp;
    private final String user;
    private final String resource;
    private final String operation;
    private final boolean success;
    private final String details;

    public AuditEvent(String user, String resource,
                      String operation, boolean success, String details) {
        this.timestamp = new Date();
        this.user = user;
        this.resource = resource;
        this.operation = operation;
        this.success = success;
        this.details = details;
    }

    @Override
    public String toString() {
        return String.format("%s | user=%s | resource=%s | op=%s | success=%s | %s",
                timestamp, user, resource, operation, success, details);
    }
}
