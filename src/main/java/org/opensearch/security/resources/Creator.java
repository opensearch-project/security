package org.opensearch.security.resources;

public enum Creator {
    USER("user");

    private final String name;

    Creator(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
