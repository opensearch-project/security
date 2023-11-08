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

package org.opensearch.security.securityconf.impl.v7;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeMap;

import com.google.common.collect.ImmutableSet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexAbstraction.Type;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.security.securityconf.ConfigModelV7.IndexPattern;
import org.opensearch.security.user.User;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@RunWith(MockitoJUnitRunner.class)
public class IndexPatternTests {

    @Mock
    private User user;
    @Mock
    private IndexNameExpressionResolver resolver;
    @Mock
    private ClusterService clusterService;

    private IndexPattern ip;

    @Before
    public void before() {
        ip = spy(new IndexPattern("defaultPattern"));
    }

    @After
    public void after() {
        verifyNoMoreInteractions(user, resolver, clusterService);
    }

    @Test
    public void testCtor() {
        assertThrows(NullPointerException.class, () -> new IndexPattern(null));
    }

    /** Ensure that concreteIndexNames sends correct parameters are sent to getResolvedIndexPattern */
    @Test
    public void testConcreteIndexNamesOverload() {
        doReturn(ImmutableSet.of("darn")).when(ip).getResolvedIndexPattern(user, resolver, clusterService, false);

        final Set<String> results = ip.concreteIndexNames(user, resolver, clusterService);

        assertThat(results, contains("darn"));

        verify(ip).getResolvedIndexPattern(user, resolver, clusterService, false);
        verify(ip).concreteIndexNames(user, resolver, clusterService);
        verifyNoMoreInteractions(ip);
    }

    /** Ensure that attemptResolveIndexNames sends correct parameters are sent to getResolvedIndexPattern */
    @Test
    public void testAttemptResolveIndexNamesOverload() {
        doReturn(ImmutableSet.of("yarn")).when(ip).getResolvedIndexPattern(user, resolver, clusterService, true);

        final Set<String> results = ip.attemptResolveIndexNames(user, resolver, clusterService);

        assertThat(results, contains("yarn"));

        verify(ip).getResolvedIndexPattern(user, resolver, clusterService, true);
        verify(ip).attemptResolveIndexNames(user, resolver, clusterService);
        verifyNoMoreInteractions(ip);
    }

    /** Verify concreteIndexNames when there are no matches */
    @Test
    public void testExactNameWithNoMatches() {
        doReturn("index-17").when(ip).getUnresolvedIndexPattern(user);
        when(clusterService.state()).thenReturn(mock(ClusterState.class));
        when(resolver.concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-17"))).thenReturn(
            new String[] {}
        );

        final Set<String> results = ip.concreteIndexNames(user, resolver, clusterService);

        assertThat(results, contains("index-17"));

        verify(clusterService).state();
        verify(ip).getUnresolvedIndexPattern(user);
        verify(resolver).concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-17"));
    }

    /** Verify concreteIndexNames on exact name matches */
    @Test
    public void testExactName() {
        doReturn("index-17").when(ip).getUnresolvedIndexPattern(user);
        when(clusterService.state()).thenReturn(mock(ClusterState.class));
        when(resolver.concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-17"))).thenReturn(
            new String[] { "resolved-index-17" }
        );

        final Set<String> results = ip.concreteIndexNames(user, resolver, clusterService);

        assertThat(results, contains("resolved-index-17"));

        verify(clusterService).state();
        verify(ip).getUnresolvedIndexPattern(user);
        verify(resolver).concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-17"));
    }

    /** Verify concreteIndexNames on multiple matches */
    @Test
    public void testMultipleConcreteIndices() {
        doReturn("index-1*").when(ip).getUnresolvedIndexPattern(user);
        doReturn(createClusterState()).when(clusterService).state();
        when(resolver.concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-1*"))).thenReturn(
            new String[] { "resolved-index-17", "resolved-index-18" }
        );

        final Set<String> results = ip.concreteIndexNames(user, resolver, clusterService);

        assertThat(results, contains("resolved-index-17", "resolved-index-18"));

        verify(clusterService, times(2)).state();
        verify(ip).getUnresolvedIndexPattern(user);
        verify(resolver).concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-1*"));
    }

    /** Verify concreteIndexNames when there is an alias */
    @Test
    public void testMultipleConcreteIndicesWithOneAlias() {
        doReturn("index-1*").when(ip).getUnresolvedIndexPattern(user);

        doReturn(
            createClusterState(
                new IndexShorthand("index-100", Type.ALIAS), // Name and type match
                new IndexShorthand("19", Type.ALIAS) // Type matches/wrong name
            )
        ).when(clusterService).state();
        when(resolver.concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-100"))).thenReturn(
            new String[] { "resolved-index-100" }
        );
        when(resolver.concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-1*"))).thenReturn(
            new String[] { "resolved-index-17", "resolved-index-18" }
        );

        final Set<String> results = ip.concreteIndexNames(user, resolver, clusterService);

        assertThat(results, contains("resolved-index-100", "resolved-index-17", "resolved-index-18"));

        verify(clusterService, times(3)).state();
        verify(ip).getUnresolvedIndexPattern(user);
        verify(resolver).concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-100"));
        verify(resolver).concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-1*"));
    }

    /** Verify attemptResolveIndexNames with multiple aliases */
    @Test
    public void testMultipleConcreteAliasedAndUnresolved() {
        doReturn("index-1*").when(ip).getUnresolvedIndexPattern(user);
        doReturn(
            createClusterState(
                new IndexShorthand("index-100", Type.ALIAS), // Name and type match
                new IndexShorthand("index-101", Type.ALIAS), // Name and type match
                new IndexShorthand("19", Type.ALIAS) // Type matches/wrong name
            )
        ).when(clusterService).state();
        when(resolver.concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-100"), eq("index-101")))
            .thenReturn(new String[] { "resolved-index-100", "resolved-index-101" });
        when(resolver.concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-1*"))).thenReturn(
            new String[] { "resolved-index-17", "resolved-index-18" }
        );

        final Set<String> results = ip.attemptResolveIndexNames(user, resolver, clusterService);

        assertThat(results, contains("resolved-index-100", "resolved-index-101", "resolved-index-17", "resolved-index-18", "index-1*"));

        verify(clusterService, times(3)).state();
        verify(ip).getUnresolvedIndexPattern(user);
        verify(resolver).concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-100"), eq("index-101"));
        verify(resolver).concreteIndexNames(any(), eq(IndicesOptions.lenientExpandOpen()), eq(true), eq("index-1*"));
    }

    private ClusterState createClusterState(final IndexShorthand... indices) {
        final TreeMap<String, IndexAbstraction> indexMap = new TreeMap<String, IndexAbstraction>();
        Arrays.stream(indices).forEach(indexShorthand -> {
            final IndexAbstraction indexAbstraction = mock(IndexAbstraction.class);
            when(indexAbstraction.getType()).thenReturn(indexShorthand.type);
            indexMap.put(indexShorthand.name, indexAbstraction);
        });

        final Metadata mockMetadata = mock(Metadata.class, withSettings().strictness(Strictness.LENIENT));
        when(mockMetadata.getIndicesLookup()).thenReturn(indexMap);

        final ClusterState mockClusterState = mock(ClusterState.class, withSettings().strictness(Strictness.LENIENT));
        when(mockClusterState.getMetadata()).thenReturn(mockMetadata);

        return mockClusterState;
    }

    private class IndexShorthand {
        public final String name;
        public final Type type;

        public IndexShorthand(final String name, final Type type) {
            this.name = name;
            this.type = type;
        }
    }
}
