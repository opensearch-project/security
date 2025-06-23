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

package org.opensearch.security.privileges;
import org.junit.Test;
import org.opensearch.action.admin.cluster.state.ClusterStateRequest;
import org.opensearch.action.admin.cluster.stats.ClusterStatsRequest;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.util.MockIndexMetadataBuilder;
import org.opensearch.security.util.MockPrivilegeEvaluationContextBuilder;

import java.util.Optional;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class IndicesRequestResolverTest {

    static final Metadata metadata = MockIndexMetadataBuilder.indices("index1", "index2", "index3").build();
    final static ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(metadata).build();
    static final IndicesRequestResolver subject = new IndicesRequestResolver(new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY)));

    @Test
    public void resolve_normal() {
        SearchRequest request = new SearchRequest("index1");
        ActionRequestMetadata<SearchRequest, ?> actionRequestMetadata = mock();
        ResolvedIndices resolvedIndices = ResolvedIndices.of("index1");
        when(actionRequestMetadata.resolvedIndices()).thenReturn(Optional.of(resolvedIndices));

        ResolvedIndices returnedResolvedIndices = subject.resolve(request, actionRequestMetadata, () -> clusterState);
        assertEquals(resolvedIndices, returnedResolvedIndices);
    }

    @Test
    public void resolve_fallback() {
        SearchRequest request = new SearchRequest("index1");
        ActionRequestMetadata<SearchRequest, ?> actionRequestMetadata = mock();
        when(actionRequestMetadata.resolvedIndices()).thenReturn(Optional.empty());

        ResolvedIndices returnedResolvedIndices = subject.resolve(request, actionRequestMetadata, () -> clusterState);
        assertEquals(Set.of("index1"), returnedResolvedIndices.local().names());
    }

    @Test
    public void resolve_fallbackUnsupported() {
        ClusterStatsRequest request = new ClusterStatsRequest();
        ActionRequestMetadata<SearchRequest, ?> actionRequestMetadata = mock();
        when(actionRequestMetadata.resolvedIndices()).thenReturn(Optional.empty());

        ResolvedIndices returnedResolvedIndices = subject.resolve(request, actionRequestMetadata, () -> clusterState);
        assertTrue("Expected isAll(), got: " + returnedResolvedIndices, returnedResolvedIndices.local().isAll());
    }

    @Test
    public void resolve_withPrivilegesEvaluationContext() {
        SearchRequest request = new SearchRequest("index*");
        ActionRequestMetadata<SearchRequest, ?> actionRequestMetadata = mock();
        when(actionRequestMetadata.resolvedIndices()).thenReturn(Optional.empty());
        PrivilegesEvaluationContext context = MockPrivilegeEvaluationContextBuilder.ctx().clusterState(clusterState).get();

        ResolvedIndices returnedResolvedIndices = subject.resolve(request, actionRequestMetadata, context);
        assertEquals(Set.of("index1", "index2", "index3"), returnedResolvedIndices.local().names());
    }
}
