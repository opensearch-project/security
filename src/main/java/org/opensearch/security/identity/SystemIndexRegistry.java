package org.opensearch.security.identity;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class SystemIndexRegistry {
    private final Map<String, Set<String>> registeredSystemIndexPatterns;

    public SystemIndexRegistry() {
        registeredSystemIndexPatterns = new HashMap<>();
    }

    public void addSystemIntexPatterns(String pluginIdentifier, Set<String> indexPatterns) {
        registeredSystemIndexPatterns.put(pluginIdentifier, indexPatterns);
    }

    public Set<String> getSystemIndexPatterns(String pluginIdentifier) {
        return registeredSystemIndexPatterns.get(pluginIdentifier);
    }
}
