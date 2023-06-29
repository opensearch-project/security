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

import java.util.Collections;
import java.util.List;

public class RoleMappings {

    private List<String> hosts = Collections.emptyList();
    private List<String> users = Collections.emptyList();

    public void setHosts(List<String> hosts) {
        this.hosts = hosts;
    }

    public List<String> getHosts() {
        return hosts;
    }

    public void setUsers(List<String> users) {
        this.users = users;
    }

    public List<String> getUsers() {
        return users;
    }
}
