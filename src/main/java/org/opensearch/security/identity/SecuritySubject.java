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

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.NamedPrincipal;
import org.opensearch.identity.Subject;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;

public class SecuritySubject implements Subject {

    private ThreadContext threadContext;

    public SecuritySubject() {}

    public void setThreadContext(ThreadContext threadContext) {
        this.threadContext = threadContext;
    }

    @Override
    public Principal getPrincipal() {
        if (threadContext == null) {
            return NamedPrincipal.UNAUTHENTICATED;
        }
        final User user = (User) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null) {
            return NamedPrincipal.UNAUTHENTICATED;
        }
        return new NamedPrincipal(user.getName());
    }

    @Override
    public void authenticate(AuthToken authToken) {
        // TODO implement this - replace with logic from SecurityRestFilter
    }
}
