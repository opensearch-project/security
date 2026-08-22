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

package org.opensearch.security.configuration;

import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.OriginalIndices;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilderVisitor;
import org.opensearch.index.query.QueryShardContext;
import org.opensearch.index.shard.IndexShard;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.internal.SearchContext;
import org.opensearch.search.startree.StarTreeQueryContext;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.dlsfls.DlsFlsBaseContext;
import org.opensearch.security.privileges.dlsfls.DlsFlsProcessedConfig;
import org.opensearch.security.privileges.dlsfls.DlsRestriction;
import org.opensearch.security.privileges.dlsfls.DocumentPrivileges;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.privileges.dlsfls.FieldPrivileges;
import org.opensearch.security.privileges.dlsfls.IndexToRuleMap;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DlsFlsValveImplTest {

    @Test
    public void appliesDlsFilterToTopLevelHybridQueryInAdaptiveMode() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(hybridQuery));

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, true, false, true, true);

        assertThat(result, is(true));
    }

    @Test
    public void usesFilterLevelDlsForTermLookupQueryInAdaptiveMode() {
        boolean result = DlsFlsValveImpl.shouldUseFilterLevelDlsInAdaptiveMode(true, true);

        assertThat(result, is(true));
    }

    @Test
    public void doesNotApplyHybridQueryFilterForTermLookupQuery() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(hybridQuery));

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, true, true, true, true);

        assertThat(result, is(false));
    }

    @Test
    public void usesLuceneLevelDlsForRegularQueryInAdaptiveMode() {
        boolean result = DlsFlsValveImpl.shouldUseFilterLevelDlsInAdaptiveMode(true, false);

        assertThat(result, is(false));
    }

    @Test
    public void doesNotUseFilterLevelDlsWithoutDlsRestrictions() {
        boolean result = DlsFlsValveImpl.shouldUseFilterLevelDlsInAdaptiveMode(false, true);

        assertThat(result, is(false));
    }

    @Test
    public void hybridQueryDlsMarkerPreventsValveReentry() throws Exception {
        org.apache.logging.log4j.core.Logger logger = (org.apache.logging.log4j.core.Logger) LogManager.getLogger(DlsFlsValveImpl.class);
        Level previousLevel = logger.getLevel();
        logger.setLevel(Level.DEBUG);
        try {
            assertDlsMarkerPreventsValveReentry(ConfigConstants.OPENDISTRO_SECURITY_HYBRID_QUERY_DLS_DONE);
        } finally {
            logger.setLevel(previousLevel);
        }
    }

    @Test
    public void filterLevelDlsMarkerPreventsValveReentry() throws Exception {
        assertDlsMarkerPreventsValveReentry("true");
    }

    private static void assertDlsMarkerPreventsValveReentry(String value) throws Exception {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE, value);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, new User("test-user"));
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        OptionallyResolvedIndices resolved = mock(OptionallyResolvedIndices.class);
        when(context.getAction()).thenReturn("indices:data/read/search[phase/query]");
        when(context.getRequest()).thenReturn(new SearchRequest());
        when(context.getResolvedIndices()).thenReturn(resolved);

        DocumentPrivileges documentPrivileges = mock(DocumentPrivileges.class);
        when(documentPrivileges.isUnrestricted(context, resolved)).thenReturn(false);
        FieldPrivileges fieldPrivileges = mock(FieldPrivileges.class);
        when(fieldPrivileges.isUnrestricted(context, resolved)).thenReturn(true);
        FieldMasking fieldMasking = mock(FieldMasking.class);
        when(fieldMasking.isUnrestricted(context, resolved)).thenReturn(true);
        DlsFlsProcessedConfig config = mock(DlsFlsProcessedConfig.class);
        when(config.getDocumentPrivileges()).thenReturn(documentPrivileges);
        when(config.getFieldPrivileges()).thenReturn(fieldPrivileges);
        when(config.getFieldMasking()).thenReturn(fieldMasking);
        DlsFlsBaseContext baseContext = mock(DlsFlsBaseContext.class);
        when(baseContext.config()).thenReturn(config);

        ClusterService clusterService = mock(ClusterService.class);
        @SuppressWarnings("unchecked")
        OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting = mock(OpensearchDynamicSetting.class);
        when(resourceSharingEnabledSetting.getDynamicSettingValue()).thenReturn(false);
        DlsFlsValveImpl valve = new DlsFlsValveImpl(
            Settings.EMPTY,
            mock(Client.class),
            clusterService,
            NamedXContentRegistry.EMPTY,
            threadPool,
            baseContext,
            mock(AdminDNs.class),
            mock(ResourcePluginInfo.class),
            resourceSharingEnabledSetting
        );

        boolean result = valve.invoke(context, mock(ActionListener.class));

        assertThat(result, is(true));
        verify(clusterService, never()).state();
    }

    @Test
    public void usesLuceneLevelDlsWhenSearchHasNoSourceInAdaptiveMode() {
        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(new SearchRequest(), true, false, true, true);

        assertThat(result, is(false));
    }

    @Test
    public void usesLuceneLevelDlsWhenSearchSourceHasNoQueryInAdaptiveMode() {
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource());

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, true, false, true, true);

        assertThat(result, is(false));
    }

    @Test
    public void usesLuceneLevelDlsForNonSearchRequestInAdaptiveMode() {
        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(
            mock(ActionRequest.class),
            true,
            false,
            true,
            true
        );

        assertThat(result, is(false));
    }

    @Test
    public void doesNotSelectDlsModeForHybridQueryWithoutDlsRestrictions() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(hybridQuery));

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, false, false, true, true);

        assertThat(result, is(false));
    }

    @Test
    public void doesNotApplyHybridQueryFilterWhenClusterContainsOlderNode() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(hybridQuery));

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, true, false, false, true);

        assertThat(result, is(false));
    }

    @Test
    public void doesNotApplyHybridQueryFilterForCrossClusterSearch() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(hybridQuery));

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, true, false, true, false);

        assertThat(result, is(false));
    }

    @Test
    public void doesNotApplyHybridQueryFilterWhenHybridQueryIsNotTopLevel() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        BoolQueryBuilder outerQuery = new BoolQueryBuilder().must(hybridQuery);
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(outerQuery));

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, true, false, true, true);

        assertThat(result, is(false));
    }

    @Test
    public void doesNotApplyHybridQueryFilterForParentChildQuery() {
        QueryBuilder parentChildQuery = mock(QueryBuilder.class);
        when(parentChildQuery.getWriteableName()).thenReturn("has_child");
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        doAnswer(invocation -> {
            QueryBuilderVisitor visitor = invocation.getArgument(0);
            visitor.accept(parentChildQuery);
            return null;
        }).when(hybridQuery).visit(any(QueryBuilderVisitor.class));
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(hybridQuery));

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, true, false, true, true);

        assertThat(result, is(false));
    }

    @Test
    public void hybridQueryDlsFilterRequiresOpenSearchThreeNineOnEveryNode() {
        assertThat(DlsFlsValveImpl.isHybridQueryDlsFilterSupported(null), is(false));
        assertThat(DlsFlsValveImpl.isHybridQueryDlsFilterSupported(Version.V_3_8_0), is(false));
        assertThat(DlsFlsValveImpl.isHybridQueryDlsFilterSupported(Version.V_3_9_0), is(true));
    }

    @Test
    public void appliesHybridQueryDlsOnlyToLocalIndices() {
        ResolvedIndices localIndices = ResolvedIndices.of("index");
        OriginalIndices originalIndices = new OriginalIndices(new String[] { "remote-index" }, IndicesOptions.strictExpandOpen());
        ResolvedIndices remoteIndices = localIndices.withRemoteIndices(Map.of("remote", originalIndices));

        assertThat(DlsFlsValveImpl.isLocalOnlyRequest(localIndices), is(true));
        assertThat(DlsFlsValveImpl.isLocalOnlyRequest(remoteIndices), is(false));
        assertThat(DlsFlsValveImpl.isLocalOnlyRequest(mock(OptionallyResolvedIndices.class)), is(false));
    }

    @Test
    public void routesEligibleHybridQueriesThroughFilterLevelDls() throws Exception {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        when(filteredHybridQuery.getName()).thenReturn("hybrid");
        when(hybridQuery.filter(any(QueryBuilder.class))).thenReturn(filteredHybridQuery);

        invokeAdaptiveDlsValve(hybridQuery, filteredHybridQuery, false);
    }

    @Test
    public void keepsRegularQueriesAtLuceneLevelDls() throws Exception {
        invokeAdaptiveDlsValve(new BoolQueryBuilder(), null, true);
    }

    private static void invokeAdaptiveDlsValve(QueryBuilder query, QueryBuilder expectedQuery, boolean expectedResult) throws Exception {
        String index = "index";
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, new User("test-user"));
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        SearchRequest searchRequest = new SearchRequest(index).source(SearchSourceBuilder.searchSource().query(query));
        ResolvedIndices resolved = ResolvedIndices.of(index);
        PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        ClusterState clusterState = mock(ClusterState.class);
        when(context.getAction()).thenReturn("indices:data/read/search");
        when(context.getRequest()).thenReturn(searchRequest);
        when(context.getResolvedIndices()).thenReturn(resolved);
        when(context.clusterState()).thenReturn(clusterState);
        when(clusterState.metadata()).thenReturn(Metadata.EMPTY_METADATA);

        DocumentPrivileges.RenderedDlsQuery renderedDlsQuery = mock(DocumentPrivileges.RenderedDlsQuery.class);
        when(renderedDlsQuery.getQueryBuilder()).thenReturn(new BoolQueryBuilder());
        DlsRestriction dlsRestriction = mock(DlsRestriction.class);
        when(dlsRestriction.getQueries()).thenReturn(ImmutableList.of(renderedDlsQuery));
        when(dlsRestriction.isUnrestricted()).thenReturn(false);
        when(dlsRestriction.containsTermLookupQuery()).thenReturn(false);
        IndexToRuleMap<DlsRestriction> restrictions = new IndexToRuleMap<>(ImmutableMap.of(index, dlsRestriction));
        DocumentPrivileges documentPrivileges = mock(DocumentPrivileges.class);
        when(documentPrivileges.isUnrestricted(context, resolved)).thenReturn(false);
        when(documentPrivileges.getRestrictions(context, resolved.local().names(clusterState))).thenReturn(restrictions);
        FieldPrivileges fieldPrivileges = mock(FieldPrivileges.class);
        when(fieldPrivileges.isUnrestricted(context, resolved)).thenReturn(true);
        FieldMasking fieldMasking = mock(FieldMasking.class);
        when(fieldMasking.isUnrestricted(context, resolved)).thenReturn(true);
        DlsFlsProcessedConfig config = mock(DlsFlsProcessedConfig.class);
        when(config.getDocumentPrivileges()).thenReturn(documentPrivileges);
        when(config.getFieldPrivileges()).thenReturn(fieldPrivileges);
        when(config.getFieldMasking()).thenReturn(fieldMasking);
        DlsFlsBaseContext baseContext = mock(DlsFlsBaseContext.class);
        when(baseContext.config()).thenReturn(config);

        DiscoveryNodes nodes = mock(DiscoveryNodes.class);
        when(nodes.getMinNodeVersion()).thenReturn(Version.V_3_9_0);
        when(clusterState.nodes()).thenReturn(nodes);
        ClusterService clusterService = mock(ClusterService.class);
        when(clusterService.state()).thenReturn(clusterState);
        @SuppressWarnings("unchecked")
        OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting = mock(OpensearchDynamicSetting.class);
        when(resourceSharingEnabledSetting.getDynamicSettingValue()).thenReturn(false);
        Client nodeClient = mock(Client.class);
        @SuppressWarnings("unchecked")
        ActionListener<Object> listener = mock(ActionListener.class);
        doAnswer(invocation -> {
            assertThat(
                threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE),
                is(ConfigConstants.OPENDISTRO_SECURITY_HYBRID_QUERY_DLS_DONE)
            );
            return null;
        }).when(nodeClient).search(any(SearchRequest.class), org.mockito.ArgumentMatchers.<ActionListener<SearchResponse>>any());
        DlsFlsValveImpl valve = new DlsFlsValveImpl(
            Settings.EMPTY,
            nodeClient,
            clusterService,
            NamedXContentRegistry.EMPTY,
            threadPool,
            baseContext,
            mock(AdminDNs.class),
            mock(ResourcePluginInfo.class),
            resourceSharingEnabledSetting
        );

        boolean result = valve.invoke(context, listener);

        assertThat(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE), is((String) null));
        if (expectedResult) {
            assertThat(searchRequest.source().query(), sameInstance(query));
            verify(nodeClient, never()).search(
                any(SearchRequest.class),
                org.mockito.ArgumentMatchers.<ActionListener<SearchResponse>>any()
            );
        } else {
            verify(nodeClient).search(any(SearchRequest.class), org.mockito.ArgumentMatchers.<ActionListener<SearchResponse>>any());
            assertThat(searchRequest.source().query(), sameInstance(expectedQuery));
        }
        assertThat(result, is(expectedResult));
    }

    @Test
    public void disablesStarTreeBeforeSkippingHybridQueryWrapping() throws Exception {
        String index = "index";
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        DlsFlsBaseContext baseContext = mock(DlsFlsBaseContext.class);
        when(baseContext.isDlsQueryFilterApplied()).thenReturn(true);
        PrivilegesEvaluationContext privilegesEvaluationContext = mock(PrivilegesEvaluationContext.class);
        when(baseContext.getPrivilegesEvaluationContext()).thenReturn(privilegesEvaluationContext);

        DlsRestriction dlsRestriction = mock(DlsRestriction.class);
        DocumentPrivileges documentPrivileges = mock(DocumentPrivileges.class);
        when(documentPrivileges.getRestriction(privilegesEvaluationContext, index)).thenReturn(dlsRestriction);
        DlsFlsProcessedConfig config = mock(DlsFlsProcessedConfig.class);
        when(config.getDocumentPrivileges()).thenReturn(documentPrivileges);
        when(config.getFieldPrivileges()).thenReturn(mock(FieldPrivileges.class));
        when(config.getFieldMasking()).thenReturn(mock(FieldMasking.class));
        when(baseContext.config()).thenReturn(config);

        SearchContext searchContext = mock(SearchContext.class);
        IndexMetadata indexMetadata = IndexMetadata.builder(index)
            .settings(Settings.builder().put(IndexMetadata.SETTING_INDEX_VERSION_CREATED.getKey(), Version.CURRENT))
            .numberOfShards(1)
            .numberOfReplicas(0)
            .build();
        IndexSettings indexSettings = new IndexSettings(indexMetadata, Settings.EMPTY);
        IndexShard indexShard = mock(IndexShard.class);
        when(indexShard.indexSettings()).thenReturn(indexSettings);
        when(searchContext.indexShard()).thenReturn(indexShard);
        QueryShardContext queryShardContext = mock(QueryShardContext.class);
        when(queryShardContext.getStarTreeQueryContext()).thenReturn(mock(StarTreeQueryContext.class));
        when(searchContext.getQueryShardContext()).thenReturn(queryShardContext);

        ClusterService clusterService = mock(ClusterService.class);
        @SuppressWarnings("unchecked")
        OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting = mock(OpensearchDynamicSetting.class);
        DlsFlsValveImpl valve = new DlsFlsValveImpl(
            Settings.EMPTY,
            mock(Client.class),
            clusterService,
            NamedXContentRegistry.EMPTY,
            threadPool,
            baseContext,
            mock(AdminDNs.class),
            mock(ResourcePluginInfo.class),
            resourceSharingEnabledSetting
        );

        valve.handleSearchContext(searchContext, threadPool);

        verify(queryShardContext).setStarTreeQueryContext(null);
        verify(dlsRestriction, never()).toBooleanQueryBuilder(any(), any());
    }
}
