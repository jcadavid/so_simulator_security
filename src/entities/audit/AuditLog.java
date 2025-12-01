package entities.audit;

import java.util.ArrayList;
import java.util.List;

/**
 * Clase que almacena el conjunto de eventos auditoria.
 */
public class AuditLog {

    private final List<AuditEvent> events = new ArrayList<>();

    public void record(AuditEvent event) {
        events.add(event);
    }

    public void print() {
        System.out.println("=== AUDIT LOG ===");
        events.forEach(System.out::println);
    }

    public List<AuditEvent> getEvents() {
        return events;
    }
}
