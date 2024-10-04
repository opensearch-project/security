package org.opensearch.security.sample;

import org.opensearch.accesscontrol.resources.ResourceAccessScope;

/**
 * This class demonstrates a sample implementation of Basic Access Scopes to fit each plugin's use-case.
 * The plugin then uses this scope when seeking access evaluation for a user on a particular resource.
 */
enum SampleResourceScope implements ResourceAccessScope {

    SAMPLE_FULL_ACCESS("sample_full_access");

    private final String name;

    SampleResourceScope(String scopeName) {
        this.name = scopeName;
    }

    public String getName() {
        return name;
    }
}
