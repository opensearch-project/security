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

import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.sameInstance;
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
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(filteredHybridQuery));
        verify(hybridQuery).filter(dlsQuery);
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
    public void usesDlsQueryWhenSearchHasNoQuery() {
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource();

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, false);

        assertThat(searchSource.query(), sameInstance(dlsQuery));
        assertThat(dlsQuery.must(), empty());
        assertThat(dlsQuery.should(), hasSize(1));
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
}
