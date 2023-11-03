/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.cluster;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.FieldSortBuilder;
import org.opensearch.search.sort.SortOrder;

import static java.util.concurrent.TimeUnit.MINUTES;

public final class SearchRequestFactory {

    private SearchRequestFactory() {

    }

    public static SearchRequest queryByIdsRequest(String indexName, String... ids) {
        SearchRequest searchRequest = new SearchRequest(indexName);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.idsQuery().addIds(ids));
        searchRequest.source(searchSourceBuilder);
        return searchRequest;
    }

    public static SearchRequest queryStringQueryRequest(String indexName, String queryString) {
        SearchRequest searchRequest = new SearchRequest(indexName);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.queryStringQuery(queryString));
        searchRequest.source(searchSourceBuilder);
        return searchRequest;
    }

    public static SearchRequest queryStringQueryRequest(String[] indicesNames, String queryString) {
        SearchRequest searchRequest = new SearchRequest(indicesNames);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.queryStringQuery(queryString));
        searchRequest.source(searchSourceBuilder);
        return searchRequest;
    }

    public static SearchRequest queryStringQueryRequest(String queryString) {
        SearchRequest searchRequest = new SearchRequest();
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.queryStringQuery(queryString));
        searchRequest.source(searchSourceBuilder);
        return searchRequest;
    }

    public static SearchRequest searchRequestWithScroll(String indexName, int pageSize) {
        SearchRequest searchRequest = new SearchRequest(indexName);
        searchRequest.scroll(new TimeValue(1, MINUTES));
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.matchAllQuery());
        searchSourceBuilder.sort(new FieldSortBuilder("_id").order(SortOrder.ASC));
        searchSourceBuilder.size(pageSize);
        searchRequest.source(searchSourceBuilder);
        return searchRequest;
    }

    public static SearchRequest searchAll(String... indexNames) {
        SearchRequest searchRequest = new SearchRequest(indexNames);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.matchAllQuery());
        searchRequest.source(searchSourceBuilder);
        return searchRequest;
    }

    public static SearchScrollRequest getSearchScrollRequest(SearchResponse searchResponse) {
        SearchScrollRequest scrollRequest = new SearchScrollRequest(searchResponse.getScrollId());
        scrollRequest.scroll(new TimeValue(1, MINUTES));
        return scrollRequest;
    }

    public static SearchRequest averageAggregationRequest(String indexName, String aggregationName, String fieldName) {
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.aggregation(AggregationBuilders.avg(aggregationName).field(fieldName));
        searchSourceBuilder.size(0);
        SearchRequest searchRequest = new SearchRequest(indexName);
        searchRequest.source(searchSourceBuilder);
        return searchRequest;
    }

    public static SearchRequest statsAggregationRequest(String indexName, String aggregationName, String fieldName) {
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.aggregation(AggregationBuilders.stats(aggregationName).field(fieldName));
        searchSourceBuilder.size(0);
        SearchRequest searchRequest = new SearchRequest(indexName);
        searchRequest.source(searchSourceBuilder);
        return searchRequest;
    }
}
