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
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link InternalOpenSearchSink#createIndexIfAbsent(String)}.
 *
 * <p>Covers the two exception branches that cannot be reliably triggered in an
 * integration test against a single-node embedded cluster:</p>
 * <ul>
 *   <li>{@code ResourceAlreadyExistsException} — thrown when two nodes race to
 *       create the same index simultaneously. The sink must treat this as success
 *       and return {@code true}.</li>
 *   <li>Generic {@code Exception} — thrown on unexpected cluster failures (e.g.,
 *       permission denied, cluster not available). The sink must absorb the error
 *       and return {@code false} without propagating the exception.</li>
 * </ul>
 *
 * <p>The remaining branches ({@code hasAlias()}, {@code hasIndex()}, and
 * successful creation) are covered by the integration tests:</p>
 * <ul>
 *   <li>{@link InternalOpenSearchSinkIntegrationTest}</li>
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
}
