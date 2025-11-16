/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.support;

public enum HostResolverMode {
    IP_HOSTNAME("ip-hostname"),
    IP_HOSTNAME_LOOKUP("ip-hostname-lookup"),
    DISABLED("disabled");

    private final String value;

    HostResolverMode(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static HostResolverMode fromConfig(String hostResolverModeConfig) {
        if (hostResolverModeConfig == null || hostResolverModeConfig.equalsIgnoreCase(IP_HOSTNAME.value)) {
            return HostResolverMode.IP_HOSTNAME;
        } else if (hostResolverModeConfig.equalsIgnoreCase(IP_HOSTNAME_LOOKUP.value)) {
            return HostResolverMode.IP_HOSTNAME_LOOKUP;
        } else {
            return HostResolverMode.DISABLED;
        }
    }
}
