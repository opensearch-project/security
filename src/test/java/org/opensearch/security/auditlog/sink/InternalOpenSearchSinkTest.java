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
package org.opensearch.security.auditlog.sink;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link InternalOpenSearchSink#createIndexIfAbsent(String)}.
 *
 * <p>Covers three branches that cannot be reliably triggered in an integration
 * test against a single-node embedded cluster:</p>
 * <ul>
 *   <li>{@code ResourceAlreadyExistsException} — thrown when two nodes race to
 *       create the same index simultaneously. The sink must treat this as success
 *       and return {@code true}.</li>
 *   <li>Generic {@code Exception} — thrown on unexpected cluster failures (e.g.,
 *       permission denied, cluster not available). The sink must absorb the error
 *       and return {@code false} without propagating the exception.</li>
 *   <li>{@code acknowledged=false} — the cluster manager accepted the request but
 *       timed out waiting for all shard copies to confirm. The index likely exists
 *       on the primary node but may not yet be visible cluster-wide. The sink must
 *       return {@code false} so the current audit event is skipped gracefully.</li>
 * </ul>
 *
 * <p>The remaining branches ({@code hasAlias()}, {@code hasIndex()}, and
 * successful creation) are covered by the integration tests:</p>
 * <ul>
 *   <li>{@link InternalOpenSearchSinkIntegrationTestConcreteIndex}</li>
 *   <li>{@link InternalOpenSearchSinkIntegrationTestAuditAlias}</li>
 * </ul>
 */
@RunWith(MockitoJUnitRunner.class)
public class InternalOpenSearchSinkTest {

    private static final String TEST_INDEX = "test-audit-index";

    @Mock private ClusterService clusterService;
    @Mock private ClusterState clusterState;
    @Mock private Metadata metadata;
    @Mock private Client client;
    @Mock private AdminClient adminClient;
    @Mock private IndicesAdminClient indicesAdminClient;
    @Mock private ThreadPool threadPool;
    @Mock private ActionFuture<CreateIndexResponse> createIndexFuture;

    private InternalOpenSearchSink sink;

    @Before
    public void setUp() {
        when(clusterService.state()).thenReturn(clusterState);
        when(clusterState.metadata()).thenReturn(metadata);
        when(metadata.hasAlias(TEST_INDEX)).thenReturn(false);
        when(metadata.hasIndex(TEST_INDEX)).thenReturn(false);
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);

        sink = new InternalOpenSearchSink(
            "test-sink",
            Settings.EMPTY,
            null,
            null,
            client,
            threadPool,
            null,
            clusterService
        );
    }

    /**
     * Verifies that {@code createIndexIfAbsent()} returns {@code true} when
     * {@link ResourceAlreadyExistsException} is thrown during index creation.
     *
     * <p><b>Scenario:</b> In a multi-node cluster, two nodes can call
     * {@code createIndexIfAbsent()} concurrently. The first node creates the index
     * successfully; the second finds {@code hasIndex()} returning {@code false}
     * (cluster state not yet propagated) and attempts creation, receiving
     * {@link ResourceAlreadyExistsException}. The sink must treat this as a
     * no-op success rather than a failure.</p>
     *
     * <p><b>Tested Code Path:</b></p>
     * <pre>{@code
     * } catch (ResourceAlreadyExistsException e) {
     *     log.debug("Audit log index '{}' was created by another node", indexName);
     *     return true;
     * }</pre>
     */
    @Test
    public void createIndexIfAbsent_returnsTrue_onConcurrentCreationByAnotherNode() {
        when(indicesAdminClient.create(any(CreateIndexRequest.class)))
            .thenThrow(new ResourceAlreadyExistsException(TEST_INDEX));

        boolean result = sink.createIndexIfAbsent(TEST_INDEX);

        assertThat("Must return true when index was concurrently created by another node",
            result, is(true));
        verify(indicesAdminClient).create(any(CreateIndexRequest.class));
    }

    /**
     * Verifies that {@code createIndexIfAbsent()} returns {@code false} when an
     * unexpected exception is thrown, without propagating it to the caller.
     *
     * <p><b>Scenario:</b> An unforeseen cluster error (e.g., node disconnection,
     * authorization failure, or I/O error) prevents index creation. The sink must
     * log the error and return {@code false} so that the calling {@code doStore()}
     * can handle the failure gracefully, rather than crashing the audit pipeline.</p>
     *
     * <p><b>Tested Code Path:</b></p>
     * <pre>{@code
     * } catch (Exception e) {
     *     log.error("Error creating audit log index '{}'", indexName, e);
     *     return false;
     * }</pre>
     */
    @Test
    public void createIndexIfAbsent_returnsFalse_onUnexpectedException() {
        when(indicesAdminClient.create(any(CreateIndexRequest.class)))
            .thenThrow(new RuntimeException("simulated cluster failure"));

        boolean result = sink.createIndexIfAbsent(TEST_INDEX);

        assertThat("Must return false without propagating the exception to the caller",
            result, is(false));
        verify(indicesAdminClient).create(any(CreateIndexRequest.class));
    }

    /**
     * Verifies that {@code createIndexIfAbsent()} returns {@code false} when the
     * cluster manager acknowledges the request but the response is not acknowledged.
     *
     * <p><b>Scenario:</b> The {@code CreateIndexRequest} completes without throwing,
     * but {@link CreateIndexResponse#isAcknowledged()} returns {@code false}. This
     * can happen when the cluster manager times out waiting for all shard copies to
     * confirm the mapping update. The index likely exists on the cluster manager node
     * but may not yet be visible to other nodes. The sink logs an error and returns
     * {@code false}, causing the current audit event to be dropped silently. The
     * next event will find the index present and succeed normally.</p>
     *
     * <p><b>Tested Code Path:</b></p>
     * <pre>{@code
     * final boolean acknowledged = clientProvider.admin().indices()
     *         .create(createIndexRequest).actionGet().isAcknowledged();
     * if (acknowledged) { ... } else {
     *     log.error("Failed to create audit log index '{}'. Index creation was not acknowledged.", indexName);
     * }
     * return acknowledged;  // returns false
     * }</pre>
     *
     * <p><b>Implementation note:</b> {@code CreateIndexResponse} is instantiated directly
     * (not mocked) because {@link org.opensearch.action.support.clustermanager.AcknowledgedResponse#isAcknowledged()}
     * is declared {@code final} and cannot be stubbed by Mockito. {@code doReturn().when()}
     * is used for {@code actionGet()} to avoid calling the generic method on the mock during
     * stub setup (type erasure would confuse the standard {@code when().thenReturn()} form).</p>
     */
    @Test
    public void createIndexIfAbsent_returnsFalse_whenCreationNotAcknowledged() {
        // CreateIndexResponse is instantiated directly because isAcknowledged() is final
        // in AcknowledgedResponse and cannot be stubbed by Mockito.
        // doReturn().when() is used instead of when().thenReturn() to avoid calling the
        // generic actionGet() on the mock during stub setup (prevents type-erasure issues).
        CreateIndexResponse notAcknowledged = new CreateIndexResponse(false, false, TEST_INDEX);
        doReturn(notAcknowledged).when(createIndexFuture).actionGet();
        when(indicesAdminClient.create(any(CreateIndexRequest.class))).thenReturn(createIndexFuture);

        boolean result = sink.createIndexIfAbsent(TEST_INDEX);

        assertThat("Must return false when index creation is not acknowledged by the cluster",
            result, is(false));
        verify(indicesAdminClient).create(any(CreateIndexRequest.class));
    }
}