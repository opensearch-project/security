/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.support;

import org.opensearch.common.settings.Settings;
import org.opensearch.indices.SystemIndexDescriptor;

/**
 * Identifies the security configuration index. The configured name is currently a concrete index;
 * aliases and backing generations are deliberately not resolved or inferred here.
 */
public final class SecurityIndexIdentity {
    private final String name;

    public SecurityIndexIdentity(Settings settings) {
        this.name = settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
    }

    public String getName() {
        return name;
    }

    public boolean isSecurityIndex(String indexName) {
        return name.equals(indexName);
    }

    public SystemIndexDescriptor getDescriptor() {
        return new SystemIndexDescriptor(name, "Security index");
    }
}
