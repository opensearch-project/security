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

package org.opensearch.test.framework.testplugins.userserialization.actions;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT;

public class TransportGetSerializedUserAction extends HandledTransportAction<GetSerializedUserRequest, GetSerializedUserResponse> {

    private final ThreadPool threadPool;

    @Inject
    public TransportGetSerializedUserAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final ThreadPool threadPool
    ) {
        super(GetSerializedUserAction.NAME, transportService, actionFilters, GetSerializedUserRequest::new);
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(Task task, GetSerializedUserRequest request, ActionListener<GetSerializedUserResponse> listener) {
        String serializedUser = threadPool.getThreadContext().getTransient(OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT);
        listener.onResponse(new GetSerializedUserResponse(serializedUser));
    }
}
