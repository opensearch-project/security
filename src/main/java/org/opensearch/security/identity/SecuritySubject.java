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

package org.opensearch.security.identity;

import java.security.Principal;

import org.opensearch.identity.NamedPrincipal;
import org.opensearch.identity.Subject;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

public class SecuritySubject implements Subject {

    private ThreadPool threadPool;

    public SecuritySubject() { }

    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }
    @Override
    public Principal getPrincipal() {
        if (threadPool == null) {
            return NamedPrincipal.UNAUTHENTICATED;
        }
        final User user = (User) threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null) {
            return NamedPrincipal.UNAUTHENTICATED;
        }
        return new NamedPrincipal(user.getName());
    }

    @Override
    public void authenticate(AuthToken authToken) {
        // TODO implement this - replace with logic from SecurityRestFilter
    }

    @Override
    public boolean isAuthenticated() {
        if (threadPool == null) {
            return false;
        }
        final User user = (User) threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        return user != null;
    }
}