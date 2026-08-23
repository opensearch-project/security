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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.BooleanClause;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollAction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.document.DocumentField;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexService;
import org.opensearch.index.get.GetResult;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilderVisitor;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.indices.IndicesService;
import org.opensearch.script.mustache.MultiSearchTemplateAction;
import org.opensearch.script.mustache.SearchTemplateAction;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.privileges.DocumentAllowList;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.dlsfls.DlsRestriction;
import org.opensearch.security.privileges.dlsfls.DocumentPrivileges;
import org.opensearch.security.privileges.dlsfls.IndexToRuleMap;
import org.opensearch.security.queries.QueryBuilderTraverser;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.ReflectiveAttributeAccessors;
import org.opensearch.security.util.ParentChildrenQueryDetector;
import org.opensearch.transport.client.Client;

public class DlsFilterLevelActionHandler {
    private static final Logger log = LogManager.getLogger(DlsFilterLevelActionHandler.class);
    private static final String HYBRID_QUERY_NAME = "hybrid";

    private static final Function<SearchRequest, String> LOCAL_CLUSTER_ALIAS_GETTER = ReflectiveAttributeAccessors.protectedObjectAttr(
        "localClusterAlias",
        String.class
    );

    public static boolean handle(
        PrivilegesEvaluationContext context,
        IndexToRuleMap<DlsRestriction> dlsRestrictionMap,
        ActionListener<?> listener,
        Client nodeClient,
        ClusterService clusterService,
        IndicesService indicesService,
        ThreadContext threadContext,
        boolean applyDlsFilterToHybridQuery
    ) {

        if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE) != null) {
            return true;
        }

        String action = context.getAction();
        ActionRequest request = context.getRequest();

        if (action.startsWith("cluster:")
            || action.startsWith("indices:admin/template/")
            || action.startsWith("indices:admin/index_template/")) {
            return true;
        }

        if (action.startsWith(SearchScrollAction.NAME)) {
            return true;
        }

        if (action.equals(SearchTemplateAction.NAME) || action.equals(MultiSearchTemplateAction.NAME)) {
            // Let it pass; DLS will be handled on a lower level
            return true;
        }

        if (request instanceof MultiSearchRequest) {
            // Let it pass; DLS will be handled on a lower level
            return true;
        }

        return new DlsFilterLevelActionHandler(
            context,
            dlsRestrictionMap,
            listener,
            nodeClient,
            clusterService,
            indicesService,
            threadContext,
            applyDlsFilterToHybridQuery
        ).handle();
    }

    private final String action;
    private final ActionRequest request;
    private final ActionListener<?> listener;
    private final IndexToRuleMap<DlsRestriction> dlsRestrictionMap;
    private final OptionallyResolvedIndices resolved;
    private final boolean requiresIndexScoping;
    private final Client nodeClient;
    private final ClusterService clusterService;
    private final IndicesService indicesService;
    private final ThreadContext threadContext;
    private final boolean applyDlsFilterToHybridQuery;
    private BoolQueryBuilder filterLevelQueryBuilder;
    private DocumentAllowList documentAllowlist;

    DlsFilterLevelActionHandler(
        PrivilegesEvaluationContext context,
        IndexToRuleMap<DlsRestriction> dlsRestrictionMap,
        ActionListener<?> listener,
        Client nodeClient,
        ClusterService clusterService,
        IndicesService indicesService,
        ThreadContext threadContext,
        boolean applyDlsFilterToHybridQuery
    ) {
        this.action = context.getAction();
        this.request = context.getRequest();
        this.listener = listener;
        this.dlsRestrictionMap = dlsRestrictionMap;
        this.resolved = context.getResolvedIndices();
        this.nodeClient = nodeClient;
        this.clusterService = clusterService;
        this.indicesService = indicesService;
        this.threadContext = threadContext;
        this.applyDlsFilterToHybridQuery = applyDlsFilterToHybridQuery;

        this.requiresIndexScoping = resolved instanceof ResolvedIndices resolvedIndices
            ? resolvedIndices.local().names().size() != 1
            : true;
    }

    private boolean handle() {

        // Snapshot the outer context without clearing the current one. The internal header added below remains active
        // while nodeClient dispatches the child request and is propagated to local search work; closing the stored
        // context restores the caller's headers.
        try (StoredContext ctx = threadContext.newStoredContext(true)) {

            threadContext.putHeader(
                ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE,
                applyDlsFilterToHybridQuery ? ConfigConstants.OPENDISTRO_SECURITY_HYBRID_QUERY_DLS_DONE : "true"
            );

            try {
                if (!modifyQuery()) {
                    return true;
                }

                if (log.isDebugEnabled()) {
                    // Do not log the request or query builder: either can contain sensitive request or DLS rule data.
                    log.debug(
                        "Created filter-level DLS query for request type {}; index scoping required: {}",
                        request.getClass().getSimpleName(),
                        requiresIndexScoping
                    );
                }

            } catch (Exception e) {
                log.error("Unable to handle filter level DLS", e);
                listener.onFailure(new OpenSearchSecurityException("Unable to handle filter level DLS", e));
                return false;
            }

            if (filterLevelQueryBuilder == null) {
                return true;
            }

            if (request instanceof SearchRequest) {
                return handle((SearchRequest) request, ctx);
            } else if (request instanceof GetRequest) {
                return handle((GetRequest) request, ctx);
            } else if (request instanceof MultiGetRequest) {
                return handle((MultiGetRequest) request, ctx);
            } else if (request instanceof ClusterSearchShardsRequest) {
                return handle((ClusterSearchShardsRequest) request, ctx);
            } else {
                log.error("Unsupported request type for filter level DLS: " + request);
                listener.onFailure(
                    new OpenSearchSecurityException(
                        "Unsupported request type for filter level DLS: " + action + "; " + request.getClass().getName()
                    )
                );
                return false;
            }
        }
    }

    private boolean handle(SearchRequest searchRequest, StoredContext ctx) {
        if (documentAllowlist != null) {
            documentAllowlist.applyTo(threadContext);
        }

        String localClusterAlias = LOCAL_CLUSTER_ALIAS_GETTER.apply(searchRequest);

        if (localClusterAlias != null) {
            try {
                modifyQuery(localClusterAlias);
            } catch (Exception e) {
                log.error("Unable to handle filter level DLS", e);
                listener.onFailure(new OpenSearchSecurityException("Unable to handle filter level DLS", e));
                return false;
            }
        }

        SearchSourceBuilder searchSource = getOrCreateSearchSource(searchRequest);
        QueryBuilder query = searchSource.query();
        if (query != null) {
            if (ParentChildrenQueryDetector.hasParentOrChildQuery(query)) {
                listener.onFailure(new OpenSearchSecurityException("Unable to handle filter level DLS for parent or child queries"));
                return false;
            }
        }

        if (!tryApplyFilterLevelDls(searchSource, filterLevelQueryBuilder, applyDlsFilterToHybridQuery, listener)) {
            return false;
        }

        nodeClient.search(searchRequest, new ActionListener<SearchResponse>() {
            @Override
            public void onResponse(SearchResponse response) {
                try {
                    ctx.restore();

                    @SuppressWarnings("unchecked")
                    ActionListener<SearchResponse> searchListener = (ActionListener<SearchResponse>) listener;

                    searchListener.onResponse(response);
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });

        return false;
    }

    static SearchSourceBuilder getOrCreateSearchSource(SearchRequest searchRequest) {
        SearchSourceBuilder searchSource = searchRequest.source();
        if (searchSource == null) {
            // A source-less search is an implicit match-all. Materialize its source so filter-level DLS can replace that
            // implicit query with the DLS restriction while retaining SearchSourceBuilder's normal defaults.
            searchSource = SearchSourceBuilder.searchSource();
            searchRequest.source(searchSource);
        }
        return searchSource;
    }

    /**
     * Applies the filter level DLS query. When {@code applyDlsFilterToHybridQuery} is true, hybrid queries remain top-level
     * and their filter method propagates the DLS restriction to every subquery. Reader-level DLS must remain active in
     * that case to retain existing DLS behavior for search features which do not use the top-level query.
     * @param searchSource
     * @param filterLevelQueryBuilder
     * @param applyDlsFilterToHybridQuery whether to push the DLS filter into a top-level hybrid query
     */
    static void applyFilterLevelDls(
        SearchSourceBuilder searchSource,
        BoolQueryBuilder filterLevelQueryBuilder,
        boolean applyDlsFilterToHybridQuery
    ) {
        QueryBuilder query = searchSource.query();
        if (query == null) {
            // No query set, apply filter level DLS query directly
            searchSource.query(filterLevelQueryBuilder);
        } else if (applyDlsFilterToHybridQuery && isHybridQuery(query)) {
            if (ParentChildrenQueryDetector.hasParentOrChildQuery(query)) {
                throw new OpenSearchSecurityException("Unable to handle filter level DLS for hybrid queries with parent or child clauses");
            }
            List<QueryBuilder> originalSubqueries = directSubqueries(query);
            if (originalSubqueries.isEmpty()) {
                throw new OpenSearchSecurityException("Hybrid query does not expose subqueries for DLS verification");
            }
            // Hybrid queries must remain top-level, so apply filter level DLS query directly
            QueryBuilder filteredHybridQuery = query.filter(filterLevelQueryBuilder);
            if (filteredHybridQuery == null) {
                throw new OpenSearchSecurityException("Hybrid query returned no query after applying the DLS filter");
            }
            if (!isHybridQuery(filteredHybridQuery)) {
                throw new OpenSearchSecurityException("Hybrid query was not preserved after applying the DLS filter");
            }
            if (!isDlsFilterAppliedToEverySubquery(filteredHybridQuery, filterLevelQueryBuilder, originalSubqueries)) {
                throw new OpenSearchSecurityException("Hybrid query did not apply the DLS filter to every subquery");
            }
            searchSource.query(filteredHybridQuery);
        } else {
            // Wrap the query in a bool query and apply filter level DLS query to it
            filterLevelQueryBuilder.must(query);
            searchSource.query(filterLevelQueryBuilder);
        }
    }

    static boolean tryApplyFilterLevelDls(
        SearchSourceBuilder searchSource,
        BoolQueryBuilder filterLevelQueryBuilder,
        boolean applyDlsFilterToHybridQuery,
        ActionListener<?> listener
    ) {
        try {
            applyFilterLevelDls(searchSource, filterLevelQueryBuilder, applyDlsFilterToHybridQuery);
            return true;
        } catch (Exception e) {
            log.error("Unable to apply filter-level DLS", e);
            listener.onFailure(
                e instanceof OpenSearchSecurityException ? e : new OpenSearchSecurityException("Unable to apply filter-level DLS", e)
            );
            return false;
        }
    }

    /**
     * Neural Search is an optional plugin, so Security identifies its hybrid query through the public query type name
     * instead of depending on its query builder class. {@link QueryBuilder#getName()} is OpenSearch's unique query type
     * identifier. A query builder registered as {@code hybrid} must expose every execution branch through its visitor.
     * Security verifies after filtering that the identity-based multiset of branches is unchanged and that each branch
     * preserves one original query while placing the exact supplied DLS query in a conjunctive boolean filter clause.
     * Branch order is deliberately ignored. Reader-level DLS remains active whenever this special path is selected.
     */
    static boolean isHybridQuery(QueryBuilder query) {
        return query != null && HYBRID_QUERY_NAME.equals(query.getName());
    }

    private static boolean isDlsFilterAppliedToEverySubquery(
        QueryBuilder filteredHybridQuery,
        QueryBuilder filterLevelQueryBuilder,
        List<QueryBuilder> originalSubqueries
    ) {
        List<QueryBuilder> filteredSubqueries = directSubqueries(filteredHybridQuery);
        if (filteredSubqueries.size() != originalSubqueries.size()) {
            return false;
        }

        Map<QueryBuilder, Integer> unmatchedOriginalSubqueries = new IdentityHashMap<>();
        originalSubqueries.forEach(originalSubquery -> unmatchedOriginalSubqueries.merge(originalSubquery, 1, Integer::sum));
        for (QueryBuilder filteredSubquery : filteredSubqueries) {
            if (!(filteredSubquery instanceof BoolQueryBuilder boolQuery)
                || boolQuery.filter().stream().noneMatch(query -> query == filterLevelQueryBuilder)) {
                return false;
            }

            QueryBuilder preservedOriginalSubquery = null;
            for (Map.Entry<QueryBuilder, Integer> entry : unmatchedOriginalSubqueries.entrySet()) {
                QueryBuilder originalSubquery = entry.getKey();
                if (entry.getValue() > 0
                    && (filteredSubquery == originalSubquery || boolQuery.must().stream().anyMatch(query -> query == originalSubquery))) {
                    if (preservedOriginalSubquery != null) {
                        // A filtered branch must not merge multiple original hybrid execution branches.
                        return false;
                    }
                    preservedOriginalSubquery = originalSubquery;
                }
            }
            if (preservedOriginalSubquery == null) {
                return false;
            }
            unmatchedOriginalSubqueries.computeIfPresent(preservedOriginalSubquery, (query, count) -> count - 1);
        }
        return true;
    }

    private static List<QueryBuilder> directSubqueries(QueryBuilder query) {
        List<QueryBuilder> directSubqueries = new ArrayList<>();
        query.visit(new DirectSubqueryCollector(directSubqueries, false));
        return directSubqueries;
    }

    private static final class DirectSubqueryCollector implements QueryBuilderVisitor {
        private final List<QueryBuilder> directSubqueries;
        private final boolean collect;

        private DirectSubqueryCollector(List<QueryBuilder> directSubqueries, boolean collect) {
            this.directSubqueries = directSubqueries;
            this.collect = collect;
        }

        @Override
        public void accept(QueryBuilder queryBuilder) {
            if (collect) {
                directSubqueries.add(queryBuilder);
            }
        }

        @Override
        public QueryBuilderVisitor getChildVisitor(BooleanClause.Occur occur) {
            return collect ? QueryBuilderVisitor.NO_OP_VISITOR : new DirectSubqueryCollector(directSubqueries, true);
        }
    }

    private boolean handle(GetRequest getRequest, StoredContext ctx) {
        if (documentAllowlist != null) {
            documentAllowlist.applyTo(threadContext);
        }

        SearchRequest searchRequest = new SearchRequest(getRequest.indices());
        BoolQueryBuilder query = QueryBuilders.boolQuery()
            .must(QueryBuilders.idsQuery().addIds(getRequest.id()))
            .must(filterLevelQueryBuilder);
        searchRequest.source(SearchSourceBuilder.searchSource().query(query));

        nodeClient.search(searchRequest, new ActionListener<SearchResponse>() {
            @Override
            public void onResponse(SearchResponse response) {
                try {

                    ctx.restore();

                    long hits = Objects.requireNonNull(response.getHits().getTotalHits()).value();

                    @SuppressWarnings("unchecked")
                    ActionListener<GetResponse> getListener = (ActionListener<GetResponse>) listener;
                    if (hits == 1) {
                        getListener.onResponse(new GetResponse(searchHitToGetResult(response.getHits().getAt(0))));
                    } else if (hits == 0) {
                        getListener.onResponse(
                            new GetResponse(
                                new GetResult(
                                    searchRequest.indices()[0],
                                    getRequest.id(),
                                    SequenceNumbers.UNASSIGNED_SEQ_NO,
                                    SequenceNumbers.UNASSIGNED_PRIMARY_TERM,
                                    -1,
                                    false,
                                    null,
                                    null,
                                    null
                                )
                            )
                        );
                    } else {
                        log.error("Unexpected hit count " + hits + " in " + response);
                        listener.onFailure(new OpenSearchSecurityException("Internal error when performing DLS"));
                    }

                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });

        return false;

    }

    private boolean handle(MultiGetRequest multiGetRequest, StoredContext ctx) {
        if (documentAllowlist != null) {
            documentAllowlist.applyTo(threadContext);
        }

        Map<String, Set<String>> idsGroupedByIndex = multiGetRequest.getItems()
            .stream()
            .collect(Collectors.groupingBy((item) -> item.index(), Collectors.mapping((item) -> item.id(), Collectors.toSet())));
        Set<String> indices = idsGroupedByIndex.keySet();
        SearchRequest searchRequest = new SearchRequest(indices.toArray(new String[indices.size()]));

        BoolQueryBuilder query;

        if (indices.size() == 1) {
            Set<String> ids = idsGroupedByIndex.get(indices.iterator().next());
            query = QueryBuilders.boolQuery()
                .must(QueryBuilders.idsQuery().addIds(ids.toArray(new String[ids.size()])))
                .must(filterLevelQueryBuilder);
        } else {
            BoolQueryBuilder mgetQuery = QueryBuilders.boolQuery().minimumShouldMatch(1);

            for (Map.Entry<String, Set<String>> entry : idsGroupedByIndex.entrySet()) {
                BoolQueryBuilder indexQuery = QueryBuilders.boolQuery()
                    .must(QueryBuilders.termQuery("_index", entry.getKey()))
                    .must(QueryBuilders.idsQuery().addIds(entry.getValue().toArray(new String[entry.getValue().size()])));

                mgetQuery.should(indexQuery);
            }

            query = QueryBuilders.boolQuery().must(mgetQuery).must(filterLevelQueryBuilder);
        }

        searchRequest.source(SearchSourceBuilder.searchSource().query(query));

        nodeClient.search(searchRequest, new ActionListener<SearchResponse>() {
            @Override
            public void onResponse(SearchResponse response) {
                try {

                    ctx.restore();

                    List<MultiGetItemResponse> itemResponses = new ArrayList<>(response.getHits().getHits().length);

                    for (SearchHit hit : response.getHits().getHits()) {
                        itemResponses.add(new MultiGetItemResponse(new GetResponse(searchHitToGetResult(hit)), null));
                    }

                    @SuppressWarnings("unchecked")
                    ActionListener<MultiGetResponse> multiGetListener = (ActionListener<MultiGetResponse>) listener;
                    multiGetListener.onResponse(
                        new MultiGetResponse(itemResponses.toArray(new MultiGetItemResponse[itemResponses.size()]))
                    );
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });

        return false;

    }

    private boolean handle(ClusterSearchShardsRequest request, StoredContext ctx) {
        listener.onFailure(
            new OpenSearchSecurityException(
                "Filter-level DLS via cross cluster search is not available for scrolling and minimize_roundtrips=true"
            )
        );
        return false;
    }

    private GetResult searchHitToGetResult(SearchHit hit) {

        if (log.isDebugEnabled()) {
            log.debug("Converting to GetResult:\n" + hit);
        }

        Map<String, DocumentField> fields = hit.getFields();
        Map<String, DocumentField> documentFields;
        Map<String, DocumentField> metadataFields;

        if (fields.isEmpty()) {
            documentFields = Collections.emptyMap();
            metadataFields = Collections.emptyMap();
        } else {
            IndexMetadata indexMetadata = clusterService.state().getMetadata().indices().get(hit.getIndex());
            IndexService indexService = indexMetadata != null ? indicesService.indexService(indexMetadata.getIndex()) : null;

            if (indexService != null) {
                documentFields = new HashMap<>(fields.size());
                metadataFields = new HashMap<>();
                MapperService mapperService = indexService.mapperService();

                for (Map.Entry<String, DocumentField> entry : fields.entrySet()) {
                    if (mapperService.isMetadataField(entry.getKey())) {
                        metadataFields.put(entry.getKey(), entry.getValue());
                    } else {
                        documentFields.put(entry.getKey(), entry.getValue());
                    }
                }

                if (log.isDebugEnabled()) {
                    log.debug("Partitioned fields: " + metadataFields + "; " + documentFields);
                }

            } else {
                if (log.isWarnEnabled()) {
                    log.warn(
                        "Could not find IndexService for "
                            + hit.getIndex()
                            + "; assuming all fields as document fields."
                            + "This should not happen, however this should also not pose a big problem as ES mixes the fields again anyway.\n"
                            + "IndexMetadata: "
                            + indexMetadata
                    );
                }

                documentFields = fields;
                metadataFields = Collections.emptyMap();
            }
        }

        return new GetResult(
            hit.getIndex(),
            hit.getId(),
            hit.getSeqNo(),
            hit.getPrimaryTerm(),
            hit.getVersion(),
            true,
            hit.getSourceRef(),
            documentFields,
            metadataFields
        );
    }

    private boolean modifyQuery() throws IOException {
        return modifyQuery(null);
    }

    private boolean modifyQuery(String localClusterAlias) throws IOException {
        Map<String, DlsRestriction> filterLevelQueries = dlsRestrictionMap.getIndexMap();

        BoolQueryBuilder dlsQueryBuilder = QueryBuilders.boolQuery().minimumShouldMatch(1);
        DocumentAllowList documentAllowlist = new DocumentAllowList();

        int queryCount = 0;

        Set<String> indices = resolved.local().names(clusterService.state());

        for (String index : indices) {
            String prefixedIndex;

            if (localClusterAlias != null) {
                prefixedIndex = localClusterAlias + ":" + index;
            } else {
                prefixedIndex = index;
            }

            DlsRestriction dlsRestriction = filterLevelQueries.get(index);

            if (dlsRestriction == null || dlsRestriction.isUnrestricted()) {
                if (requiresIndexScoping) {
                    // This index has no DLS configured, thus it is unrestricted.
                    // To allow the index in a complex query, we need to add the query below to let the index pass.
                    dlsQueryBuilder.should(QueryBuilders.termQuery("_index", prefixedIndex));
                }
                continue;
            }

            for (DocumentPrivileges.RenderedDlsQuery parsedDlsQuery : dlsRestriction.getQueries()) {
                queryCount++;

                if (!requiresIndexScoping) {
                    dlsQueryBuilder.should(parsedDlsQuery.getQueryBuilder());
                } else {
                    // The original request referred to several indices. That's why we have to scope each query to the index it is meant for
                    dlsQueryBuilder.should(
                        QueryBuilders.boolQuery()
                            .must(QueryBuilders.termQuery("_index", prefixedIndex))
                            .must(parsedDlsQuery.getQueryBuilder())
                    );
                }

                Set<QueryBuilder> queryBuilders = QueryBuilderTraverser.findAll(
                    parsedDlsQuery.getQueryBuilder(),
                    (q) -> (q instanceof TermsQueryBuilder) && ((TermsQueryBuilder) q).termsLookup() != null
                );

                for (QueryBuilder queryBuilder : queryBuilders) {
                    TermsQueryBuilder termsQueryBuilder = (TermsQueryBuilder) queryBuilder;
                    final var lookupIndex = termsQueryBuilder.termsLookup().index();
                    final var lookupId = termsQueryBuilder.termsLookup().id();

                    if (lookupId != null) {
                        documentAllowlist.add(lookupIndex, lookupId);
                    } else {
                        documentAllowlist.add(lookupIndex, DocumentAllowList.ANY_DOCUMENT_ID);
                    }
                }
            }

        }

        if (queryCount == 0) {
            // Return false to indicate that no query manipulation is necessary
            return false;
        } else {
            this.filterLevelQueryBuilder = dlsQueryBuilder;
            this.documentAllowlist = documentAllowlist;
            return true;
        }
    }

}
