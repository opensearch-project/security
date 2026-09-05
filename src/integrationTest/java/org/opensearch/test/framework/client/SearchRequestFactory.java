/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.client;

import java.util.Arrays;

import org.opensearch.client.opensearch._types.FieldSort;
import org.opensearch.client.opensearch._types.SortOptions;
import org.opensearch.client.opensearch._types.SortOrder;
import org.opensearch.client.opensearch._types.Time;
import org.opensearch.client.opensearch._types.aggregations.Aggregation;
import org.opensearch.client.opensearch._types.query_dsl.QueryBuilders;
import org.opensearch.client.opensearch.core.ScrollRequest;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;

public final class SearchRequestFactory {
    private SearchRequestFactory() {

    }

    public static SearchRequest searchRequestWithSort(String indexName) {
        return SearchRequest.of(
            r -> r.index(indexName).sort(SortOptions.of(s -> s.field(FieldSort.of(f -> f.field("_id").order(SortOrder.Asc)))))
        );
    }

    public static SearchRequest averageAggregationRequest(String indexName, String aggregationName, String fieldName) {
        return SearchRequest.of(
            r -> r.index(indexName).size(0).aggregations(aggregationName, Aggregation.of(a -> a.avg(v -> v.field(fieldName))))
        );
    }

    public static SearchRequest statsAggregationRequest(String indexName, String aggregationName, String fieldName) {
        return SearchRequest.of(
            r -> r.index(indexName).size(0).aggregations(aggregationName, Aggregation.of(a -> a.stats(v -> v.field(fieldName))))
        );
    }

    public static SearchRequest queryStringQueryRequest(String[] indicesNames, String queryString) {
        return SearchRequest.of(
            r -> r.index(Arrays.asList(indicesNames)).query(QueryBuilders.queryString().query(queryString).build().toQuery())
        );
    }

    public static SearchRequest queryStringQueryRequest(String queryString) {
        return SearchRequest.of(r -> r.query(QueryBuilders.queryString().query(queryString).build().toQuery()));
    }

    public static SearchRequest queryStringQueryRequest(String indexName, String queryString) {
        return SearchRequest.of(r -> r.index(indexName).query(QueryBuilders.queryString().query(queryString).build().toQuery()));
    }

    public static SearchRequest searchRequestWithScroll(String indexName, int pageSize) {
        return SearchRequest.of(
            r -> r.index(indexName)
                .scroll(Time.of(t -> t.time("1m")))
                .query(QueryBuilders.matchAll().build().toQuery())
                .size(pageSize)
                .sort(SortOptions.of(s -> s.field(FieldSort.of(f -> f.field("_id").order(SortOrder.Asc)))))
        );
    }

    public static ScrollRequest getSearchScrollRequest(SearchResponse<?> searchResponse) {
        return ScrollRequest.of(r -> r.scrollId(searchResponse.scrollId()).scroll(Time.of(t -> t.time("1m"))));
    }

    public static SearchRequest queryByIdsRequest(String indexName, String... ids) {
        return SearchRequest.of(
            r -> r.index(Arrays.asList(indexName)).query(QueryBuilders.ids().values(Arrays.asList(ids)).build().toQuery())
        );
    }
}
