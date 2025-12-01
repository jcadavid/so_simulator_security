package entities.user;

import entities.permissons.SecurityLevel;

/**
 * Entidad para definir el usuario y sus detalles en el nivel de seguridad
 * @param password Esto en un entorno real debería estar encriptado bajo alguna manera.
 */
public record User(String name, String password, boolean admin, SecurityLevel level) {
}
