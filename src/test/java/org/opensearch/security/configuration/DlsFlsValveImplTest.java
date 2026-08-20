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
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
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
}
