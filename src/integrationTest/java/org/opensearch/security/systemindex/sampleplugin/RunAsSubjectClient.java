/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.systemindex.sampleplugin;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.identity.Subject;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.FilterClient;

/**
 * Implementation of client that will run transport actions in a stashed context and inject the name of the provided
 * subject into the context.
 */
public class RunAsSubjectClient extends FilterClient {

    private static final Logger logger = LogManager.getLogger(RunAsSubjectClient.class);

    private Subject subject;

    public RunAsSubjectClient(Client delegate) {
        super(delegate);
    }

    public RunAsSubjectClient(Client delegate, Subject subject) {
        super(delegate);
        this.subject = subject;
    }

    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    @Override
    protected <Request extends ActionRequest, Response extends ActionResponse> void doExecute(
        ActionType<Response> action,
        Request request,
        ActionListener<Response> listener
    ) {
        try (ThreadContext.StoredContext ctx = threadPool().getThreadContext().newStoredContext(false)) {
            subject.runAs(() -> {
                logger.info("Running transport action with subject: {}", subject.getPrincipal().getName());
                super.doExecute(action, request, ActionListener.runBefore(listener, ctx::restore));
                return null;
            });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
