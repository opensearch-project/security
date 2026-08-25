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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.lucene.search.BooleanClause;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.ConstantScoreQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilderVisitor;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.dlsfls.DlsRestriction;
import org.opensearch.security.privileges.dlsfls.DocumentPrivileges;
import org.opensearch.security.privileges.dlsfls.IndexToRuleMap;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DlsFilterLevelActionHandlerTest {

    @Test
    public void appliesDlsAsFilterToTopLevelHybridQuery() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder originalSubquery = QueryBuilders.boolQuery().must(QueryBuilders.matchAllQuery());
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(hybridQuery));
        assertThat(dlsQuery.must(), empty());
        assertThat(dlsQuery.should(), hasSize(1));
        verify(hybridQuery).filter(dlsQuery);
    }

    @Test
    public void preservesImplicitMinimumShouldMatchWhenFilteringHybridBoolSubquery() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder originalSubquery = QueryBuilders.boolQuery().should(QueryBuilders.termQuery("signal", "first"));
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(originalSubquery.minimumShouldMatch(), is("1"));
        assertThat(originalSubquery.filter(), contains(sameInstance(dlsQuery)));
    }

    @Test
    public void preservesConstantScoreHybridSubqueryWhenFiltering() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        ConstantScoreQueryBuilder originalSubquery = QueryBuilders.constantScoreQuery(QueryBuilders.termQuery("signal", "first"));
        originalSubquery.boost(2.0f);
        originalSubquery.queryName("original-constant-score");
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        ConstantScoreQueryBuilder filteredSubquery = (ConstantScoreQueryBuilder) subqueries[0];
        BoolQueryBuilder filteredInnerQuery = (BoolQueryBuilder) filteredSubquery.innerQuery();
        assertThat(filteredSubquery.boost(), is(2.0f));
        assertThat(filteredSubquery.queryName(), is("original-constant-score"));
        assertThat(filteredInnerQuery.must(), contains(sameInstance(originalSubquery.innerQuery())));
        assertThat(filteredInnerQuery.filter(), contains(sameInstance(dlsQuery)));
    }

    @Test
    public void acceptsHybridSubqueryThatAppliesFilterInPlace() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        NeuralQueryBuilderContract originalSubquery = mock(NeuralQueryBuilderContract.class);
        QueryBuilder[] subqueries = { originalSubquery };
        QueryBuilder[] embeddedFilter = { null };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        doAnswer(invocation -> {
            invocation.<QueryBuilderVisitor>getArgument(0).accept(originalSubquery);
            return null;
        }).when(originalSubquery).visit(any(QueryBuilderVisitor.class));
        when(originalSubquery.getName()).thenReturn("neural");
        when(originalSubquery.queryfilter()).thenAnswer(invocation -> embeddedFilter[0]);
        when(originalSubquery.filter(dlsQuery)).thenAnswer(invocation -> {
            embeddedFilter[0] = dlsQuery;
            return originalSubquery;
        });
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(hybridQuery));
        verify(originalSubquery).filter(dlsQuery);
    }

    @Test
    public void failsClosedWhenNeuralFilterIsNotStored() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        NeuralQueryBuilderContract originalSubquery = mock(NeuralQueryBuilderContract.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubDirectSubquery(originalSubquery);
        when(originalSubquery.getName()).thenReturn("neural");
        when(originalSubquery.queryfilter()).thenReturn(null);
        when(originalSubquery.filter(dlsQuery)).thenReturn(originalSubquery);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
    }

    @Test
    public void failsClosedWhenNeuralFilterAccessorIsUnavailable() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder neuralQuery = mock(QueryBuilder.class);
        QueryBuilder[] subqueries = { neuralQuery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubDirectSubquery(neuralQuery);
        when(neuralQuery.getName()).thenReturn("neural");

        RuntimeException exception = assertThrows(
            RuntimeException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage().startsWith("Error while invoking queryfilter on "), is(true));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
        verify(hybridQuery, never()).filter(dlsQuery);
    }

    @Test
    public void preservesImplicitMinimumShouldMatchInNeuralFilter() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        NeuralQueryBuilderContract originalSubquery = mock(NeuralQueryBuilderContract.class);
        BoolQueryBuilder neuralFilter = QueryBuilders.boolQuery().should(QueryBuilders.termQuery("signal", "first"));
        QueryBuilder[] subqueries = { originalSubquery };
        QueryBuilder[] embeddedFilter = { neuralFilter };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubDirectSubquery(originalSubquery);
        when(originalSubquery.getName()).thenReturn("neural");
        when(originalSubquery.queryfilter()).thenAnswer(invocation -> embeddedFilter[0]);
        when(originalSubquery.filter(dlsQuery)).thenAnswer(invocation -> {
            embeddedFilter[0] = embeddedFilter[0].filter(dlsQuery);
            return originalSubquery;
        });
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(neuralFilter.minimumShouldMatch(), is("1"));
        assertThat(neuralFilter.filter(), contains(sameInstance(dlsQuery)));
    }

    @Test
    public void preservesConstantScoreMetadataInNeuralFilter() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        NeuralQueryBuilderContract originalSubquery = mock(NeuralQueryBuilderContract.class);
        ConstantScoreQueryBuilder originalFilter = QueryBuilders.constantScoreQuery(QueryBuilders.termQuery("signal", "first"));
        originalFilter.boost(2.0f);
        originalFilter.queryName("named-neural-filter");
        QueryBuilder[] subqueries = { originalSubquery };
        QueryBuilder[] embeddedFilter = { originalFilter };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubDirectSubquery(originalSubquery);
        when(originalSubquery.getName()).thenReturn("neural");
        when(originalSubquery.queryfilter()).thenAnswer(invocation -> embeddedFilter[0]);
        when(originalSubquery.filter(dlsQuery)).thenAnswer(invocation -> {
            embeddedFilter[0] = embeddedFilter[0].filter(dlsQuery);
            return originalSubquery;
        });
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        ConstantScoreQueryBuilder filteredEmbeddedFilter = (ConstantScoreQueryBuilder) embeddedFilter[0];
        assertThat(filteredEmbeddedFilter.boost(), is(2.0f));
        assertThat(filteredEmbeddedFilter.queryName(), is("named-neural-filter"));
    }

    @Test
    public void acceptsNeuralSparseHybridSubqueryWithDefaultFilter() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder originalSubquery = mock(QueryBuilder.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        BoolQueryBuilder filteredSubquery = QueryBuilders.boolQuery().must(originalSubquery).filter(dlsQuery);
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        doAnswer(invocation -> {
            invocation.<QueryBuilderVisitor>getArgument(0).accept(originalSubquery);
            return null;
        }).when(originalSubquery).visit(any(QueryBuilderVisitor.class));
        when(originalSubquery.getName()).thenReturn("neural_sparse");
        when(originalSubquery.filter(dlsQuery)).thenReturn(filteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(hybridQuery));
        verify(originalSubquery).filter(dlsQuery);
    }

    @Test
    public void acceptsKnnHybridSubqueryWithFilterCopy() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract originalSubquery = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract filteredSubquery = mock(KnnQueryBuilderContract.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(originalSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, null);
        stubKnnQuery(filteredSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, dlsQuery);
        when(originalSubquery.filter(dlsQuery)).thenReturn(filteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(hybridQuery));
        verify(originalSubquery).filter(dlsQuery);
    }

    @Test
    public void acceptsKnnHybridSubqueryWithOpaqueSnapshotValues() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract originalSubquery = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract filteredSubquery = mock(KnnQueryBuilderContract.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(originalSubquery, "embedding", "opaque-vector", 10, null);
        stubKnnQuery(filteredSubquery, "embedding", "opaque-vector", 10, dlsQuery);
        when(originalSubquery.getMethodParameters()).thenReturn(null);
        when(filteredSubquery.getMethodParameters()).thenReturn(null);
        when(originalSubquery.filter(dlsQuery)).thenReturn(filteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void acceptsKnnHybridSubqueryWithStructuralFallback() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract originalSubquery = mock(KnnQueryBuilderContract.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        BoolQueryBuilder filteredSubquery = QueryBuilders.boolQuery().must(originalSubquery).filter(dlsQuery);
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(originalSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, null);
        when(originalSubquery.filter(dlsQuery)).thenReturn(filteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void failsClosedWhenAnyKnnQueryParameterChanges() {
        assertKnnSemanticChangeRejected((original, filtered) -> when(filtered.fieldName()).thenReturn("other_embedding"));
        assertKnnSemanticChangeRejected((original, filtered) -> when(filtered.vector()).thenReturn(new float[] { 9.0f, 9.0f }));
        assertKnnSemanticChangeRejected((original, filtered) -> when(filtered.getK()).thenReturn(20));
        assertKnnSemanticChangeRejected((original, filtered) -> when(filtered.getMaxDistance()).thenReturn(0.5f));
        assertKnnSemanticChangeRejected((original, filtered) -> when(filtered.getMinScore()).thenReturn(0.5f));
        assertKnnSemanticChangeRejected((original, filtered) -> doReturn(Map.of("ef_search", 100)).when(filtered).getMethodParameters());
        assertKnnSemanticChangeRejected((original, filtered) -> when(filtered.isIgnoreUnmapped()).thenReturn(true));
        assertKnnSemanticChangeRejected((original, filtered) -> when(filtered.getRescoreContext()).thenReturn(new Object()));
        assertKnnSemanticChangeRejected((original, filtered) -> when(filtered.getExpandNested()).thenReturn(true));
    }

    @Test
    public void failsClosedWhenKnnMutableParametersChangeDuringFiltering() {
        float[] vector = { 1.0f, 2.0f };
        assertKnnInPlaceMutationRejected(vector, new HashMap<>(), () -> vector[0] = 9.0f);

        Map<String, Integer> methodParameters = new HashMap<>(Map.of("ef_search", 10));
        assertKnnInPlaceMutationRejected(new float[] { 1.0f, 2.0f }, methodParameters, () -> methodParameters.put("ef_search", 100));
    }

    @Test
    public void acceptsMultipleKnnHybridSubqueries() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract firstOriginal = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract secondOriginal = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract firstFiltered = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract secondFiltered = mock(KnnQueryBuilderContract.class);
        QueryBuilder[] subqueries = { firstOriginal, secondOriginal };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(firstOriginal, "first_embedding", new float[] { 1.0f, 2.0f }, 10, null);
        stubKnnQuery(secondOriginal, "second_embedding", new float[] { 3.0f, 4.0f }, 20, null);
        stubKnnQuery(firstFiltered, "first_embedding", new float[] { 1.0f, 2.0f }, 10, dlsQuery);
        stubKnnQuery(secondFiltered, "second_embedding", new float[] { 3.0f, 4.0f }, 20, dlsQuery);
        when(firstOriginal.filter(dlsQuery)).thenReturn(firstFiltered);
        when(secondOriginal.filter(dlsQuery)).thenReturn(secondFiltered);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = firstOriginal.filter(dlsQuery);
            subqueries[1] = secondOriginal.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void failsClosedWhenKnnFilterIsNotStored() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract originalSubquery = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract filteredSubquery = mock(KnnQueryBuilderContract.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(originalSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, null);
        stubKnnQuery(filteredSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, null);
        when(originalSubquery.filter(dlsQuery)).thenReturn(filteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
    }

    @Test
    public void failsClosedWhenKnnCopyChangesQuerySemantics() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract originalSubquery = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract filteredSubquery = mock(KnnQueryBuilderContract.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(originalSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, null);
        stubKnnQuery(filteredSubquery, "other_embedding", new float[] { 9.0f, 9.0f }, 10, dlsQuery);
        when(originalSubquery.filter(dlsQuery)).thenReturn(filteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
    }

    @Test
    public void preservesKnnQueryMetadata() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract originalSubquery = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract filteredSubquery = mock(KnnQueryBuilderContract.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(originalSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, null);
        stubKnnQuery(filteredSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, dlsQuery);
        when(originalSubquery.boost()).thenReturn(2.0f);
        when(originalSubquery.queryName()).thenReturn("named-knn");
        when(originalSubquery.filter(dlsQuery)).thenReturn(filteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        verify(filteredSubquery).boost(2.0f);
        verify(filteredSubquery).queryName("named-knn");
    }

    @Test
    public void preservesConstantScoreMetadataInKnnFilter() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract originalSubquery = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract filteredSubquery = mock(KnnQueryBuilderContract.class);
        ConstantScoreQueryBuilder originalFilter = QueryBuilders.constantScoreQuery(QueryBuilders.termQuery("signal", "first"));
        originalFilter.boost(2.0f);
        originalFilter.queryName("named-knn-filter");
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        QueryBuilder filteredEmbeddedFilter = originalFilter.filter(dlsQuery);
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(originalSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, originalFilter);
        stubKnnQuery(filteredSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, filteredEmbeddedFilter);
        when(originalSubquery.filter(dlsQuery)).thenReturn(filteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        ConstantScoreQueryBuilder constantScoreFilter = (ConstantScoreQueryBuilder) filteredEmbeddedFilter;
        assertThat(constantScoreFilter.boost(), is(2.0f));
        assertThat(constantScoreFilter.queryName(), is("named-knn-filter"));
    }

    @Test
    public void preservesMetadataOrderForEqualKnnSubqueries() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract firstOriginal = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract secondOriginal = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract firstFiltered = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract secondFiltered = mock(KnnQueryBuilderContract.class);
        QueryBuilder[] subqueries = { firstOriginal, secondOriginal };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(firstOriginal, "embedding", new float[] { 1.0f, 2.0f }, 10, null);
        stubKnnQuery(secondOriginal, "embedding", new float[] { 1.0f, 2.0f }, 10, null);
        stubKnnQuery(firstFiltered, "embedding", new float[] { 1.0f, 2.0f }, 10, dlsQuery);
        stubKnnQuery(secondFiltered, "embedding", new float[] { 1.0f, 2.0f }, 10, dlsQuery);
        when(firstOriginal.boost()).thenReturn(2.0f);
        when(firstOriginal.queryName()).thenReturn("first-knn");
        when(secondOriginal.boost()).thenReturn(3.0f);
        when(secondOriginal.queryName()).thenReturn("second-knn");
        when(firstOriginal.filter(dlsQuery)).thenReturn(firstFiltered);
        when(secondOriginal.filter(dlsQuery)).thenReturn(secondFiltered);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = firstOriginal.filter(dlsQuery);
            subqueries[1] = secondOriginal.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        verify(firstFiltered).boost(2.0f);
        verify(firstFiltered).queryName("first-knn");
        verify(secondFiltered).boost(3.0f);
        verify(secondFiltered).queryName("second-knn");
    }

    @Test
    public void preservesImplicitMinimumShouldMatchInKnnFilter() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract originalSubquery = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract filteredSubquery = mock(KnnQueryBuilderContract.class);
        BoolQueryBuilder knnFilter = QueryBuilders.boolQuery().should(QueryBuilders.termQuery("signal", "first"));
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(originalSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, knnFilter);
        stubKnnQuery(filteredSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, knnFilter);
        when(originalSubquery.filter(dlsQuery)).thenAnswer(invocation -> {
            knnFilter.filter(dlsQuery);
            return filteredSubquery;
        });
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(knnFilter.minimumShouldMatch(), is("1"));
        assertThat(knnFilter.filter(), contains(sameInstance(dlsQuery)));
    }

    @Test
    public void failsClosedWhenKnnFilterDoesNotMatchOriginalSubquery() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder originalSubquery = QueryBuilders.termQuery("signal", "original");
        QueryBuilder filteredSubquery = mock(QueryBuilder.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubDirectSubquery(filteredSubquery);
        when(filteredSubquery.getName()).thenReturn("knn");
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = filteredSubquery;
            return hybridQuery;
        });

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void usesQueryReturnedByHybridFilter() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        QueryBuilder firstSubquery = QueryBuilders.termQuery("signal", "first");
        QueryBuilder secondSubquery = QueryBuilders.termQuery("signal", "second");
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, firstSubquery, secondSubquery);
        stubHybridQuery(filteredHybridQuery, firstSubquery.filter(dlsQuery), secondSubquery.filter(dlsQuery));
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(filteredHybridQuery));
        verify(hybridQuery).filter(dlsQuery);
    }

    @Test
    public void acceptsFilteredHybridSubqueriesInDifferentOrder() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        QueryBuilder firstSubquery = QueryBuilders.termQuery("signal", "first");
        QueryBuilder secondSubquery = QueryBuilders.termQuery("signal", "second");
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, firstSubquery, secondSubquery);
        stubHybridQuery(filteredHybridQuery, secondSubquery.filter(dlsQuery), firstSubquery.filter(dlsQuery));
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(filteredHybridQuery));
    }

    @Test
    public void acceptsEqualHybridSubqueriesInDifferentOrder() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        QueryBuilder firstSubquery = QueryBuilders.termQuery("signal", "same");
        QueryBuilder secondSubquery = QueryBuilders.termQuery("signal", "same");
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        assertThat(firstSubquery, not(sameInstance(secondSubquery)));
        assertThat(firstSubquery, is(secondSubquery));
        stubHybridQuery(hybridQuery, firstSubquery, secondSubquery);
        stubHybridQuery(filteredHybridQuery, secondSubquery.filter(dlsQuery), firstSubquery.filter(dlsQuery));
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(filteredHybridQuery));
    }

    @Test
    public void acceptsSameHybridSubqueryInstanceTwice() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        QueryBuilder originalSubquery = QueryBuilders.termQuery("signal", "same");
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, originalSubquery, originalSubquery);
        stubHybridQuery(filteredHybridQuery, originalSubquery.filter(dlsQuery), originalSubquery.filter(dlsQuery));
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true);

        assertThat(searchSource.query(), sameInstance(filteredHybridQuery));
    }

    @Test
    public void failsClosedWhenHybridFilterDoesNotReachEverySubquery() {
        QueryBuilder firstSubquery = QueryBuilders.termQuery("signal", "first");
        QueryBuilder secondSubquery = QueryBuilders.termQuery("signal", "second");
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, firstSubquery, secondSubquery);
        stubHybridQuery(filteredHybridQuery, firstSubquery.filter(dlsQuery), secondSubquery);
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void failsClosedWhenHybridFilterDropsSubquery() {
        QueryBuilder firstSubquery = QueryBuilders.termQuery("signal", "first");
        QueryBuilder secondSubquery = QueryBuilders.termQuery("signal", "second");
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, firstSubquery, secondSubquery);
        stubHybridQuery(filteredHybridQuery, firstSubquery.filter(dlsQuery));
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void failsClosedWhenHybridFilterDuplicatesOneSubquery() {
        QueryBuilder firstSubquery = QueryBuilders.termQuery("signal", "first");
        QueryBuilder secondSubquery = QueryBuilders.termQuery("signal", "second");
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, firstSubquery, secondSubquery);
        stubHybridQuery(filteredHybridQuery, firstSubquery.filter(dlsQuery), firstSubquery.filter(dlsQuery));
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void failsClosedWhenHybridFilterMergesOriginalSubqueries() {
        QueryBuilder firstSubquery = QueryBuilders.termQuery("signal", "first");
        QueryBuilder secondSubquery = QueryBuilders.termQuery("signal", "second");
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        BoolQueryBuilder mergedSubquery = QueryBuilders.boolQuery().must(firstSubquery).must(secondSubquery).filter(dlsQuery);
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, firstSubquery, secondSubquery);
        stubHybridQuery(filteredHybridQuery, mergedSubquery, firstSubquery.filter(dlsQuery));
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void failsClosedWhenHybridNameDoesNotExposeSubqueries() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        when(hybridQuery.getName()).thenReturn("hybrid");

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query does not expose subqueries for DLS verification"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
        verify(hybridQuery, never()).filter(dlsQuery);
    }

    @Test
    public void failsClosedWhenHybridFilterIsOnlyOptional() {
        QueryBuilder originalSubquery = QueryBuilders.matchAllQuery();
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        BoolQueryBuilder unsafeFilteredSubquery = QueryBuilders.boolQuery().should(originalSubquery).should(dlsQuery);
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, originalSubquery);
        stubHybridQuery(filteredHybridQuery, unsafeFilteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void failsClosedWhenHybridFilterUsesDifferentFilter() {
        QueryBuilder originalSubquery = QueryBuilders.matchAllQuery();
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        BoolQueryBuilder wrongFilteredSubquery = QueryBuilders.boolQuery()
            .must(originalSubquery)
            .filter(QueryBuilders.termQuery("tenant", "other"));
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, originalSubquery);
        stubHybridQuery(filteredHybridQuery, wrongFilteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenReturn(filteredHybridQuery);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    @Test
    public void failsClosedWhenHybridFilterReturnsNull() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, QueryBuilders.matchAllQuery());
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

        stubHybridQuery(hybridQuery, QueryBuilders.matchAllQuery());
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

        stubHybridQuery(hybridQuery, QueryBuilders.matchAllQuery());
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
    public void wrapsUnexpectedHybridFilterFailureForActionListener() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);
        IllegalStateException failure = new IllegalStateException("filter failed");
        @SuppressWarnings("unchecked")
        ActionListener<Object> listener = mock(ActionListener.class);

        stubHybridQuery(hybridQuery, QueryBuilders.matchAllQuery());
        when(hybridQuery.filter(dlsQuery)).thenThrow(failure);

        boolean applied = DlsFilterLevelActionHandler.tryApplyFilterLevelDls(searchSource, dlsQuery, true, listener);

        assertThat(applied, is(false));
        verify(listener).onFailure(
            org.mockito.ArgumentMatchers.argThat(
                exception -> exception instanceof OpenSearchSecurityException
                    && exception.getMessage().equals("Unable to apply filter-level DLS")
                    && exception.getCause() == failure
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
    public void failsClosedWhenNeuralFilterContainsParentChildClause() {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        NeuralQueryBuilderContract neuralQuery = mock(NeuralQueryBuilderContract.class);
        QueryBuilder parentChildQuery = mock(QueryBuilder.class);
        QueryBuilder[] subqueries = { neuralQuery };
        QueryBuilder[] embeddedFilter = { parentChildQuery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        BoolQueryBuilder filteredEmbeddedQuery = QueryBuilders.boolQuery().must(parentChildQuery).filter(dlsQuery);
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubDirectSubquery(neuralQuery);
        stubDirectSubquery(parentChildQuery);
        when(neuralQuery.getName()).thenReturn("neural");
        when(neuralQuery.queryfilter()).thenAnswer(invocation -> embeddedFilter[0]);
        when(parentChildQuery.getWriteableName()).thenReturn("has_child");
        when(parentChildQuery.filter(dlsQuery)).thenReturn(filteredEmbeddedQuery);
        when(neuralQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            embeddedFilter[0] = parentChildQuery.filter(dlsQuery);
            return neuralQuery;
        });
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = neuralQuery.filter(dlsQuery);
            return hybridQuery;
        });

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
        assertDlsMarkerPreventsReentry(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE);
    }

    @Test
    public void hybridQueryDlsMarkerPreventsReentry() {
        assertDlsMarkerPreventsReentry(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_FILTER_APPLIED);
    }

    @Test
    public void scopesFilterLevelCompletionStateToChildRequest() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        SearchRequest searchRequest = new SearchRequest("index");
        ResolvedIndices resolved = ResolvedIndices.of("index");
        @SuppressWarnings("unchecked")
        IndexToRuleMap<DlsRestriction> restrictions = mock(IndexToRuleMap.class);
        ClusterService clusterService = mock(ClusterService.class);

        when(context.getAction()).thenReturn("indices:data/read/search");
        when(context.getRequest()).thenReturn(searchRequest);
        when(context.getResolvedIndices()).thenReturn(resolved);
        when(clusterService.state()).thenReturn(mock(ClusterState.class));
        when(restrictions.getIndexMap()).thenAnswer(invocation -> {
            assertThat(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE), is("true"));
            return ImmutableMap.of();
        });

        boolean result = DlsFilterLevelActionHandler.handle(
            context,
            restrictions,
            mock(ActionListener.class),
            mock(Client.class),
            clusterService,
            null,
            threadContext,
            false
        );

        assertThat(result, is(true));
        assertThat(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE), is((String) null));
    }

    @Test
    public void dispatchesHybridSearchWithHybridCompletionState() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        QueryBuilder filteredHybridQuery = mock(QueryBuilder.class);
        QueryBuilder originalSubquery = QueryBuilders.matchAllQuery();
        QueryBuilder[] filteredSubqueries = new QueryBuilder[1];
        SearchRequest searchRequest = new SearchRequest("index").source(SearchSourceBuilder.searchSource().query(hybridQuery));
        DocumentPrivileges.RenderedDlsQuery renderedDlsQuery = mock(DocumentPrivileges.RenderedDlsQuery.class);
        DlsRestriction dlsRestriction = new DlsRestriction(List.of(renderedDlsQuery));
        IndexToRuleMap<DlsRestriction> restrictions = new IndexToRuleMap<>(ImmutableMap.of("index", dlsRestriction));
        PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        ClusterService clusterService = mock(ClusterService.class);
        Client nodeClient = mock(Client.class);
        @SuppressWarnings("unchecked")
        ActionListener<Object> listener = mock(ActionListener.class);

        stubHybridQuery(hybridQuery, originalSubquery);
        stubHybridQuery(filteredHybridQuery, filteredSubqueries);
        when(hybridQuery.filter(any(QueryBuilder.class))).thenAnswer(invocation -> {
            filteredSubqueries[0] = originalSubquery.filter(invocation.getArgument(0));
            return filteredHybridQuery;
        });
        when(renderedDlsQuery.getQueryBuilder()).thenReturn(QueryBuilders.termQuery("tenant", "allowed"));
        when(context.getAction()).thenReturn("indices:data/read/search");
        when(context.getRequest()).thenReturn(searchRequest);
        when(context.getResolvedIndices()).thenReturn(ResolvedIndices.of("index"));
        when(clusterService.state()).thenReturn(mock(ClusterState.class));
        doAnswer(invocation -> {
            assertThat(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE), is((String) null));
            assertThat(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_FILTER_APPLIED), is("true"));
            return null;
        }).when(nodeClient).search(any(SearchRequest.class), org.mockito.ArgumentMatchers.<ActionListener<SearchResponse>>any());

        org.apache.logging.log4j.core.Logger logger = (org.apache.logging.log4j.core.Logger) LogManager.getLogger(
            DlsFilterLevelActionHandler.class
        );
        Level previousLevel = logger.getLevel();
        logger.setLevel(Level.DEBUG);
        try {
            boolean result = DlsFilterLevelActionHandler.handle(
                context,
                restrictions,
                listener,
                nodeClient,
                clusterService,
                null,
                threadContext,
                true
            );

            assertThat(result, is(false));
            assertThat(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE), is((String) null));
            assertThat(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_FILTER_APPLIED), is((String) null));
            assertThat(searchRequest.source().query(), sameInstance(filteredHybridQuery));
            verify(nodeClient).search(any(SearchRequest.class), org.mockito.ArgumentMatchers.<ActionListener<SearchResponse>>any());
        } finally {
            logger.setLevel(previousLevel);
        }
    }

    @Test
    public void reportsHybridFilterFailureFromHandler() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        SearchRequest searchRequest = new SearchRequest("index").source(SearchSourceBuilder.searchSource().query(hybridQuery));
        DocumentPrivileges.RenderedDlsQuery renderedDlsQuery = mock(DocumentPrivileges.RenderedDlsQuery.class);
        DlsRestriction dlsRestriction = new DlsRestriction(List.of(renderedDlsQuery));
        IndexToRuleMap<DlsRestriction> restrictions = new IndexToRuleMap<>(ImmutableMap.of("index", dlsRestriction));
        PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        ClusterService clusterService = mock(ClusterService.class);
        Client nodeClient = mock(Client.class);
        @SuppressWarnings("unchecked")
        ActionListener<Object> listener = mock(ActionListener.class);

        stubHybridQuery(hybridQuery, QueryBuilders.matchAllQuery());
        when(hybridQuery.filter(any(QueryBuilder.class))).thenReturn(null);
        when(renderedDlsQuery.getQueryBuilder()).thenReturn(QueryBuilders.termQuery("tenant", "allowed"));
        when(context.getAction()).thenReturn("indices:data/read/search");
        when(context.getRequest()).thenReturn(searchRequest);
        when(context.getResolvedIndices()).thenReturn(ResolvedIndices.of("index"));
        when(clusterService.state()).thenReturn(mock(ClusterState.class));

        boolean result = DlsFilterLevelActionHandler.handle(
            context,
            restrictions,
            listener,
            nodeClient,
            clusterService,
            null,
            threadContext,
            true
        );

        assertThat(result, is(false));
        assertThat(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE), is((String) null));
        assertThat(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_FILTER_APPLIED), is((String) null));
        verify(listener).onFailure(
            org.mockito.ArgumentMatchers.argThat(
                exception -> exception instanceof OpenSearchSecurityException
                    && exception.getMessage().equals("Hybrid query returned no query after applying the DLS filter")
            )
        );
        verify(nodeClient, never()).search(any(SearchRequest.class), org.mockito.ArgumentMatchers.<ActionListener<SearchResponse>>any());
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

    private static void stubHybridQuery(QueryBuilder hybridQuery, QueryBuilder... subqueries) {
        when(hybridQuery.getName()).thenReturn("hybrid");
        doAnswer(invocation -> {
            QueryBuilderVisitor visitor = invocation.getArgument(0);
            visitor.accept(hybridQuery);
            QueryBuilderVisitor subqueryVisitor = visitor.getChildVisitor(BooleanClause.Occur.MUST);
            for (QueryBuilder subquery : subqueries) {
                subquery.visit(subqueryVisitor);
            }
            return null;
        }).when(hybridQuery).visit(any(QueryBuilderVisitor.class));
    }

    private static void stubDirectSubquery(QueryBuilder subquery) {
        doAnswer(invocation -> {
            invocation.<QueryBuilderVisitor>getArgument(0).accept(subquery);
            return null;
        }).when(subquery).visit(any(QueryBuilderVisitor.class));
    }

    private static void stubKnnQuery(KnnQueryBuilderContract query, String fieldName, Object vector, Integer k, QueryBuilder filter) {
        doAnswer(invocation -> {
            QueryBuilderVisitor visitor = invocation.getArgument(0);
            visitor.accept(query);
            if (filter != null) {
                filter.visit(visitor.getChildVisitor(BooleanClause.Occur.FILTER));
            }
            return null;
        }).when(query).visit(any(QueryBuilderVisitor.class));
        when(query.getName()).thenReturn("knn");
        when(query.fieldName()).thenReturn(fieldName);
        when(query.vector()).thenReturn(vector);
        when(query.getK()).thenReturn(k);
        when(query.getMethodParameters()).thenReturn(Map.of());
        when(query.getFilter()).thenReturn(filter);
        when(query.boost()).thenReturn(1.0f);
    }

    private static void assertKnnSemanticChangeRejected(BiConsumer<KnnQueryBuilderContract, KnnQueryBuilderContract> semanticChange) {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract originalSubquery = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract filteredSubquery = mock(KnnQueryBuilderContract.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(originalSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, null);
        stubKnnQuery(filteredSubquery, "embedding", new float[] { 1.0f, 2.0f }, 10, dlsQuery);
        semanticChange.accept(originalSubquery, filteredSubquery);
        when(originalSubquery.filter(dlsQuery)).thenReturn(filteredSubquery);
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    private static void assertKnnInPlaceMutationRejected(Object vector, Map<String, ?> methodParameters, Runnable mutation) {
        QueryBuilder hybridQuery = mock(QueryBuilder.class);
        KnnQueryBuilderContract originalSubquery = mock(KnnQueryBuilderContract.class);
        KnnQueryBuilderContract filteredSubquery = mock(KnnQueryBuilderContract.class);
        QueryBuilder[] subqueries = { originalSubquery };
        BoolQueryBuilder dlsQuery = createDlsQuery();
        SearchSourceBuilder searchSource = SearchSourceBuilder.searchSource().query(hybridQuery);

        stubHybridQuery(hybridQuery, subqueries);
        stubKnnQuery(originalSubquery, "embedding", vector, 10, null);
        stubKnnQuery(filteredSubquery, "embedding", vector, 10, dlsQuery);
        doReturn(methodParameters).when(originalSubquery).getMethodParameters();
        doReturn(methodParameters).when(filteredSubquery).getMethodParameters();
        when(originalSubquery.filter(dlsQuery)).thenAnswer(invocation -> {
            mutation.run();
            return filteredSubquery;
        });
        when(hybridQuery.filter(dlsQuery)).thenAnswer(invocation -> {
            subqueries[0] = originalSubquery.filter(dlsQuery);
            return hybridQuery;
        });

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> DlsFilterLevelActionHandler.applyFilterLevelDls(searchSource, dlsQuery, true)
        );

        assertThat(exception.getMessage(), is("Hybrid query did not apply the DLS filter to every subquery"));
        assertThat(searchSource.query(), sameInstance(hybridQuery));
    }

    private interface NeuralQueryBuilderContract extends QueryBuilder {
        QueryBuilder queryfilter();
    }

    private interface KnnQueryBuilderContract extends QueryBuilder {
        String fieldName();

        Object vector();

        Integer getK();

        Float getMaxDistance();

        Float getMinScore();

        Map<String, ?> getMethodParameters();

        QueryBuilder getFilter();

        boolean isIgnoreUnmapped();

        Object getRescoreContext();

        Boolean getExpandNested();
    }

    private static void assertDlsMarkerPreventsReentry(String header) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putHeader(header, "true");

        boolean result = DlsFilterLevelActionHandler.handle(null, null, null, null, null, null, threadContext, false);

        assertThat(result, is(true));
    }
}
