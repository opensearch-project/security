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

import java.util.Map;
import java.util.Set;

public interface InMemorySecurityRoles extends SecurityRoles {

    void addSecurityRole(String roleName, Set<String> clusterPerms, Map<String, Set<String>> indexPatternToAllowedActions);
}
