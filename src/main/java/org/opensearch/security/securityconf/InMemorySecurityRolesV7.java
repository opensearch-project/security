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

package org.opensearch.security.securityconf;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.opensearch.security.support.WildcardMatcher;

public class InMemorySecurityRolesV7 extends ConfigModelV7.SecurityRoles implements InMemorySecurityRoles {

    public InMemorySecurityRolesV7(int roleCount) {
        super(roleCount);
    }

    @Override
    public void addSecurityRole(String roleName, Set<String> clusterPerms, Map<String, Set<String>> indexPatternToAllowedActions) {
        Set<ConfigModelV7.IndexPattern> ipatterns = new HashSet<>();
        for (Map.Entry<String, Set<String>> entry : indexPatternToAllowedActions.entrySet()) {
            ConfigModelV7.IndexPattern idxPattern = new ConfigModelV7.IndexPattern(entry.getKey());
            idxPattern.addPerm(entry.getValue());
            ipatterns.add(idxPattern);
        }
        ConfigModelV7.SecurityRole role = new ConfigModelV7.SecurityRole(roleName, ipatterns, WildcardMatcher.from(clusterPerms));
        roles.add(role);
    }
}
