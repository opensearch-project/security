/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.auth;

import java.security.Principal;

import org.opensearch.common.CheckedRunnable;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.NamedPrincipal;
import org.opensearch.identity.UserSubject;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

public class UserSubjectImpl implements UserSubject {
    private final NamedPrincipal userPrincipal;
    private final ThreadPool threadPool;
    private final User user;

    UserSubjectImpl(ThreadPool threadPool, User user) {
        this.threadPool = threadPool;
        this.user = user;
        this.userPrincipal = new NamedPrincipal(user.getName());
    }

    @Override
    public void authenticate(AuthToken authToken) {
        // not implemented
    }

    @Override
    public Principal getPrincipal() {
        return userPrincipal;
    }

    @Override
    public <E extends Exception> void runAs(CheckedRunnable<E> r) throws E {
        try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
            threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
            r.run();
        }
    }

    public User getUser() {
        return user;
    }
}
