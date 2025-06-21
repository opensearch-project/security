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

import org.opensearch.common.CheckedRunnable;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.NamedPrincipal;
import org.opensearch.identity.PluginSubject;
import org.opensearch.threadpool.ThreadPool;

public class NoopPluginSubject implements PluginSubject {
    private final ThreadPool threadPool;

    public NoopPluginSubject(ThreadPool threadPool) {
        super();
        this.threadPool = threadPool;
    }

    @Override
    public Principal getPrincipal() {
        return NamedPrincipal.UNAUTHENTICATED;
    }

    @Override
    public <E extends Exception> void runAs(CheckedRunnable<E> r) throws E {
        try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
            r.run();
        }
    }
}
