package org.opensearch.security.resources;

public enum Recipient {
    USERS("users"),
    ROLES("roles"),
    BACKEND_ROLES("backend_roles");

    private final String name;

    Recipient(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
