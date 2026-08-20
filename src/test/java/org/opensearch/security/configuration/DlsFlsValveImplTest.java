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

import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.query.QueryBuilder;
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
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
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

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, true, false, true);

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

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, true, true, true);

        assertThat(result, is(false));
    }

    @Test
    public void usesLuceneLevelDlsForRegularQueryInAdaptiveMode() {
        boolean result = DlsFlsValveImpl.shouldUseFilterLevelDlsInAdaptiveMode(true, false);

        assertThat(result, is(false));
    }

    @Test
    public void usesLuceneLevelDlsWhenSearchHasNoSourceInAdaptiveMode() {
        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(new SearchRequest(), true, false, true);

        assertThat(result, is(false));
    }

    @Test
    public void usesLuceneLevelDlsForNonSearchRequestInAdaptiveMode() {
        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(mock(ActionRequest.class), true, false, true);

        assertThat(result, is(false));
    }

    @Test
    public void doesNotSelectDlsModeForHybridQueryWithoutDlsRestrictions() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(hybridQuery));

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, false, false, true);

        assertThat(result, is(false));
    }

    @Test
    public void doesNotApplyHybridQueryFilterWhenClusterContainsOlderNode() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        when(hybridQuery.getName()).thenReturn("hybrid");
        SearchRequest searchRequest = new SearchRequest().source(SearchSourceBuilder.searchSource().query(hybridQuery));

        boolean result = DlsFlsValveImpl.shouldApplyDlsFilterToHybridQueryInAdaptiveMode(searchRequest, true, false, false);

        assertThat(result, is(false));
    }

    @Test
    public void hybridQueryDlsFilterRequiresOpenSearchThreeNineOnEveryNode() {
        assertThat(DlsFlsValveImpl.isHybridQueryDlsFilterSupported(null), is(false));
        assertThat(DlsFlsValveImpl.isHybridQueryDlsFilterSupported(Version.V_3_8_0), is(false));
        assertThat(DlsFlsValveImpl.isHybridQueryDlsFilterSupported(Version.V_3_9_0), is(true));
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
