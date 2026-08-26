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

package org.opensearch.security.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.user.User;

public final class RemoteClusterIdentityPolicy {

    private static final Logger log = LogManager.getLogger(RemoteClusterIdentityPolicy.class);

    private volatile boolean ignoreSourceSecurityRoles;

    public RemoteClusterIdentityPolicy(boolean ignoreSourceSecurityRoles) {
        this.ignoreSourceSecurityRoles = ignoreSourceSecurityRoles;
    }

    public void setIgnoreSourceSecurityRoles(boolean value) {
        this.ignoreSourceSecurityRoles = value;
    }

    /**
     * Strips source-propagated securityRoles on trusted cluster (CCS) requests when
     * {@code plugins.security.ccs.ignore_source_security_roles} is enabled.
     * For non-CCS requests, the User is returned unchanged.
     */
    User sanitize(User user, ThreadContext threadContext) {
        if (ignoreSourceSecurityRoles && HeaderHelper.isRemoteClusterNodeRequest(threadContext)) {
            log.debug("Stripping source-propagated securityRoles for CCS user [{}]", user.getName());
            return user.withoutSecurityRoles();
        }
        return user;
    }
}
