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

import org.apache.lucene.search.BooleanClause;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilderVisitor;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DlsFilterLevelActionHandlerTest {

    @Test
    public void appliesDlsAsFilterToTopLevelHybridQuery() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        when(hybridQuery.getName()).thenReturn("hybrid");
        when(hybridQuery.filter(dlsQuery)).thenReturn(hybridQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(hybridQuery));
        assertThat(dlsQuery.must(), empty());
        assertThat(dlsQuery.should(), hasSize(1));
        verify(hybridQuery).filter(dlsQuery);
    }

    @Test
    public void usesQueryReturnedByHybridFilter() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        when(hybridQuery.getName()).thenReturn("hybrid");
        when(filteredHybridQuery.getName()).thenReturn("hybrid");
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(filteredHybridQuery));
        verify(hybridQuery).filter(dlsQuery);
    }

    @Test
    public void failsClosedWhenHybridFilterReturnsNull() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        when(hybridQuery.getName()).thenReturn("hybrid");
        when(hybridQuery.filter(dlsQuery)).thenReturn(null);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query returned no query after applying the DLS filter"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void failsClosedWhenHybridFilterReturnsNonHybridQuery() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder nonHybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        when(hybridQuery.getName()).thenReturn("hybrid");
        when(nonHybridQuery.getName()).thenReturn("bool");
        when(hybridQuery.filter(dlsQuery)).thenReturn(nonHybridQuery);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query was not preserved after applying the DLS filter"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void reportsHybridFilterFailureToActionListener() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);
        @SuppressWarnings("unchecked")
        ActionListener<Object> listener = mock(ActionListener.class);

        when(hybridQuery.getName()).thenReturn("hybrid");
        when(hybridQuery.filter(dlsQuery)).thenReturn(null);

        boolean applied = DlsFilterLevelActionHandler.tryApplyFilterLevelDls(searchSource, dlsQuery, true, listener);

        assertThat(applied, is(false));
        verify(listener).onFailure(
            org.mockito.ArgumentMatchers.argThat(
                exception -> exception instanceof OpenSearchSecurityException
                    && exception.getMessage().equals("Hybrid query returned no query after applying the DLS filter")
            )
        );
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void failsClosedWhenHybridQueryContainsParentChildClause() {
        QueryBuilder parentChildQuery = mock(QueryBuilder.class);
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        when(parentChildQuery.getWriteableName()).thenReturn("has_child");
        when(hybridQuery.getName()).thenReturn("hybrid");
        doAnswer(invocation -> {
            QueryBuilderVisitor visitor = invocation.getArgument(0);
            visitor.accept(hybridQuery);
            visitor.getChildVisitor(BooleanClause.Occur.MUST).accept(parentChildQuery);
            return null;
        }).when(hybridQuery).visit(any(QueryBuilderVisitor.class));

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Unable to handle filter level DLS for hybrid queries with parent or child clauses"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
        verify(hybridQuery, never()).filter(dlsQuery);
    }

    @Test
    public void wrapsNonHybridQueryWithDlsQuery() {
        QueryBuilder originalQuery = QueryBuilders.matchAllQuery();
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(originalQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, false);

        assertThat(searchSource.query(), sameInstance(dlsQuery));
        assertThat(dlsQuery.must(), contains(sameInstance(originalQuery)));
        assertThat(dlsQuery.should(), hasSize(1));
    }

    @Test
    public void wrapsNonHybridQueryEvenWhenHybridFilterFlagIsSet() {
        QueryBuilder originalQuery = QueryBuilders.matchAllQuery();
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(originalQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(dlsQuery));
        assertThat(dlsQuery.must(), contains(sameInstance(originalQuery)));
    }

    @Test
    public void usesDlsQueryWhenSearchHasNoQuery() {
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource();

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, false);

        assertThat(searchSource.query(), sameInstance(dlsQuery));
        assertThat(dlsQuery.must(), empty());
        assertThat(dlsQuery.should(), hasSize(1));
    }

    @Test
    public void createsSearchSourceAndAppliesDlsWhenSearchHasNoSource() {
        SearchRequest searchRequest = new SearchRequest();
        BoolQueryBuilder dlsQuery = createDlsQuery();

        SearchSourceBuilder searchSource = DlsFilterLevelActionHandler.getOrCreateSearchSource(searchRequest);
        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, false);

        assertThat(searchRequest.source(), sameInstance(searchSource));
        assertThat(searchSource.query(), sameInstance(dlsQuery));
        assertThat(dlsQuery.must(), empty());
        assertThat(dlsQuery.should(), hasSize(1));
    }

    @Test
    public void preservesExistingSearchSource() {
        SearchSourceBuilder existingSearchSource = SearchSourceBuilder.searchSource().query(QueryBuilders.matchAllQuery());
        SearchRequest searchRequest = new SearchRequest().source(existingSearchSource);

        SearchSourceBuilder searchSource = DlsFilterLevelActionHandler.getOrCreateSearchSource(searchRequest);

        assertThat(searchSource, sameInstance(existingSearchSource));
        assertThat(searchRequest.source(), sameInstance(existingSearchSource));
    }

    @Test
    public void filterLevelDlsMarkerPreventsReentry() {
        assertDlsMarkerPreventsReentry("true");
    }

    @Test
    public void hybridQueryDlsMarkerPreventsReentry() {
        assertDlsMarkerPreventsReentry(ConfigConstants.OPENDISTRO_SECURITY_HYBRID_QUERY_DLS_DONE);
    }

    @Test
    public void unmarkedClusterActionUsesNormalDispatchChecks() {
        PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        when(context.getAction()).thenReturn("cluster:test");
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);

        boolean result = DlsFilterLevelActionHandler.handle(context, null, null, null, null, null, threadContext, false);

        assertThat(result, is(true));
    }

    @Test
    public void wrapsHybridQueryWhenReaderLevelDlsIsNotPreserved() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        when(hybridQuery.getName()).thenReturn("hybrid");

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, false);

        assertThat(searchSource.query(), sameInstance(dlsQuery));
        assertThat(dlsQuery.must(), contains(sameInstance(hybridQuery)));
        verify(hybridQuery, never()).filter(dlsQuery);
    }

    private static BoolQueryBuilder createDlsQuery() {
        return QueryBuilders.boolQuery().minimumShouldMatch(1).should(QueryBuilders.termQuery("tenant", "allowed"));
    }

    private static void assertDlsMarkerPreventsReentry(String value) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE, value);

        boolean result = DlsFilterLevelActionHandler.handle(null, null, null, null, null, null, threadContext, false);

        assertThat(result, is(true));
    }
}
