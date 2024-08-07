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
package org.opensearch.security.privileges.dlsfls;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;

/**
 * Node global context data for DLS/FLS. The lifecycle of an instance of this class is equal to the lifecycle of a running node.
 */
public class DlsFlsBaseContext {
    private final PrivilegesEvaluator privilegesEvaluator;
    private final ThreadContext threadContext;
    private final AdminDNs adminDNs;

    public DlsFlsBaseContext(PrivilegesEvaluator privilegesEvaluator, ThreadContext threadContext, AdminDNs adminDNs) {
        this.privilegesEvaluator = privilegesEvaluator;
        this.threadContext = threadContext;
        this.adminDNs = adminDNs;
    }

    /**
     * Returns the PrivilegesEvaluationContext for the current thread. Returns null if the current thread is not
     * associated with a user. This indicates a system action. In these cases, no privilege evaluation should be performed.
     */
    public PrivilegesEvaluationContext getPrivilegesEvaluationContext() {
        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

        if (user == null || adminDNs.isAdmin(user)) {
            return null;
        }

        return this.privilegesEvaluator.createContext(user, null);
    }

    public boolean isDlsDoneOnFilterLevel() {
        if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE) != null) {
            return true;
        } else {
            return false;
        }
    }
}
