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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

/**
 * Transport action that persists a Security configuration document and then broadcasts a
 * {@link ConfigUpdateAction} so every node reloads the affected config. The listener is only
 * completed once the cluster-wide reload has been acknowledged, mirroring exactly the sync path
 * in {@code AbstractApiAction.saveAndUpdateConfigsAsync}.
 *
 * <p>The whole operation runs under one {@link Task}. When a REST client submits with
 * {@code wait_for_completion=false}, the task result is stored in {@code .tasks} and can be
 * polled via {@code GET /_tasks/{id}}. Cancellation is not supported (see
 * {@link SecurityConfigWriteAction} class-level docs).
 */
public class TransportSecurityConfigWriteAction extends HandledTransportAction<SecurityConfigWriteRequest, SecurityConfigWriteResponse> {

    private static final Logger LOGGER = LogManager.getLogger(TransportSecurityConfigWriteAction.class);

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
        final IndexRequest indexRequest = new IndexRequest(request.getSecurityIndex()).id(request.getCType())
            .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .setIfSeqNo(request.getSeqNo())
            .setIfPrimaryTerm(request.getPrimaryTerm())
            .source(request.getCType(), request.getContent());

        // Step 1: write the config document. Optimistic concurrency is enforced by the
        // (seqNo, primaryTerm) preconditions above — a stale write surfaces as
        // VersionConflictEngineException and is propagated to the task listener untouched.
        client.index(indexRequest, ActionListener.wrap(indexResponse -> {
            // Step 2: fan out a reload request so every node re-reads the changed config from
            // the index. This is the same mechanism the pre-existing sync path uses via
            // ConfigUpdatingActionListener. We only complete the task listener after every node
            // acknowledges, so callers polling _tasks/{id} see the operation as in-progress
            // until the cluster is consistent.
            final var configUpdate = new org.opensearch.security.action.configupdate.ConfigUpdateRequest(
                new String[] { request.getCType() }
            );
            client.execute(ConfigUpdateAction.INSTANCE, configUpdate, ActionListener.wrap(configUpdateResponse -> {
                if (configUpdateResponse.hasFailures()) {
                    // Surface the first per-node failure. The full failure list is available on
                    // configUpdateResponse for anyone consuming the raw response object, but the
                    // stored task result only carries the exception message.
                    listener.onFailure(configUpdateResponse.failures().get(0));
                    return;
                }
                listener.onResponse(new SecurityConfigWriteResponse(request.getSuccessStatus(), request.getSuccessMessage()));
            }, e -> {
                LOGGER.debug("Cluster-wide config reload failed for {}", request.getCType(), e);
                listener.onFailure(e);
            }));
        }, e -> {
            LOGGER.debug("Persisting configuration to security index failed for {}", request.getCType(), e);
            listener.onFailure(e);
        }));
    }
}
