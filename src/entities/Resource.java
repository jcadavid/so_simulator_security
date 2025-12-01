package entities;

import entities.permissons.Permission;
import entities.permissons.SecurityLevel;
import entities.user.User;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

public class Resource {

    private final String name;
    private final User owner;
    private final SecurityLevel level;
    private final boolean critical;

    // Usamos EnumSet para simular los permisos que poseen los usuarios dueños del recurso
    private EnumSet<Permission> ownerPermissions = EnumSet.noneOf(Permission.class);
    // Usamos EnumSet para simular los permisos que poseen otros usuarios
    private EnumSet<Permission> othersPermissions = EnumSet.noneOf(Permission.class);

    /** Usamos un Map para realizar una implementación simple de ACL,
     * indicando como la key el user y
     * un EnumSet de permisos específicos
     */
    private final Map<String, EnumSet<Permission>> acl = new HashMap<>();

    public Resource(String name, User owner, SecurityLevel level, boolean critical) {
        this.name = name;
        this.owner = owner;
        this.level = level;
        this.critical = critical;
    }

    public String getName() {
        return name;
    }

    public User getOwner() {
        return owner;
    }

    public SecurityLevel getLevel() {
        return level;
    }

    public boolean isCritical() {
        return critical;
    }

    public EnumSet<Permission> getOwnerPermissions() {
        return ownerPermissions;
    }

    public void setOwnerPermissions(EnumSet<Permission> ownerPermissions) {
        this.ownerPermissions = ownerPermissions;
    }

    public EnumSet<Permission> getOthersPermissions() {
        return othersPermissions;
    }

    public void setOthersPermissions(EnumSet<Permission> othersPermissions) {
        this.othersPermissions = othersPermissions;
    }

    public Map<String, EnumSet<Permission>> getAcl() {
        return acl;
    }

    public void addAclEntry(String userName, EnumSet<Permission> permissions) {
        acl.put(userName, permissions);
    }
}
