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

package org.opensearch.security.action.configupdate;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.dlic.rest.api.AbstractApiAction;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

/**
 * Transport action that persists a Security configuration document and then broadcasts a
 * {@link ConfigUpdateAction} so every node reloads the affected config. Delegates all of the
 * mechanical work (index write, per-node fan-out, all-node-ack wait) to the shared
 * {@link AbstractApiAction.ConfigUpdatingActionListener} chain — the same code path the
 * synchronous save uses. Any future change to write or reload semantics automatically applies to
 * both paths.
 *
 * <p>The whole operation runs under one {@link Task}. When a REST client submits with
 * {@code wait_for_completion=false}, the task result is stored in {@code .tasks} and can be
 * polled via {@code GET /_tasks/{id}}. Cancellation is not supported (see
 * {@link SecurityConfigWriteAction} class-level docs).
 */
public class TransportSecurityConfigWriteAction extends HandledTransportAction<SecurityConfigWriteRequest, SecurityConfigWriteResponse> {

    private final Client client;

    @Inject
    public TransportSecurityConfigWriteAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final Client client
    ) {
        super(SecurityConfigWriteAction.NAME, transportService, actionFilters, SecurityConfigWriteRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(
        final Task task,
        final SecurityConfigWriteRequest request,
        final ActionListener<SecurityConfigWriteResponse> listener
    ) {
        // Wire the pre-built IndexRequest through the shared ConfigUpdatingActionListener. The
        // listener already handles: (1) the actual index write, (2) fan-out of ConfigUpdateAction
        // to every node, (3) collecting all-node acknowledgements before completing, (4) surfacing
        // the first per-node failure if any node fails to reload.
        client.index(
            request.getIndexRequest(),
            new AbstractApiAction.ConfigUpdatingActionListener<>(
                new String[] { request.getCType() },
                client,
                ActionListener.wrap(
                    indexResponse -> listener.onResponse(
                        new SecurityConfigWriteResponse(request.getSuccessStatus(), request.getSuccessMessage())
                    ),
                    listener::onFailure
                )
            )
        );
    }
}
