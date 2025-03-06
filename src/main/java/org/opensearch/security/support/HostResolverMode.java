package org.opensearch.security.support;

public enum HostResolverMode {
    IP_HOSTNAME("ip-hostname"),
    IP_HOSTNAME_LOOKUP("ip-hostname-lookup");

    private final String value;

    HostResolverMode(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
