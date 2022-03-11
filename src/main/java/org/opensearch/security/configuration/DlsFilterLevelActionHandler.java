/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.configuration;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionListener;
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
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.document.DocumentField;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.index.IndexService;
import org.opensearch.index.get.GetResult;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.indices.IndicesService;
import org.opensearch.script.mustache.MultiSearchTemplateAction;
import org.opensearch.script.mustache.SearchTemplateAction;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.privileges.DocumentAllowList;
import org.opensearch.security.queries.QueryBuilderTraverser;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.securityconf.EvaluatedDlsFlsConfig;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.ReflectiveAttributeAccessors;
import org.opensearch.security.support.SecurityUtils;

public class DlsFilterLevelActionHandler {
    private static final Logger log = LoggerFactory.getLogger(DlsFilterLevelActionHandler.class);

    private static final Function<SearchRequest, String> LOCAL_CLUSTER_ALIAS_GETTER = ReflectiveAttributeAccessors
            .protectedObjectAttr("localClusterAlias", String.class);

    public static boolean handle(String action, ActionRequest request, ActionListener<?> listener, EvaluatedDlsFlsConfig evaluatedDlsFlsConfig,
                                 Resolved resolved, Client nodeClient, ClusterService clusterService, IndicesService indicesService,
                                 IndexNameExpressionResolver resolver, DlsQueryParser dlsQueryParser, ThreadContext threadContext) {

        if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE) != null) {
            return true;
        }

        if (action.startsWith("cluster:") || action.startsWith("indices:admin/template/")
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

        return new DlsFilterLevelActionHandler(action, request, listener, evaluatedDlsFlsConfig, resolved, nodeClient, clusterService, indicesService,
                resolver, dlsQueryParser, threadContext).handle();
    }

    private final String action;
    private final ActionRequest request;
    private final ActionListener<?> listener;
    private final EvaluatedDlsFlsConfig evaluatedDlsFlsConfig;
    private final Resolved resolved;
    private final boolean requiresIndexScoping;
    private final Client nodeClient;
    private final DlsQueryParser dlsQueryParser;
    private final ClusterService clusterService;
    private final IndicesService indicesService;
    private final ThreadContext threadContext;
    private final IndexNameExpressionResolver resolver;
    private BoolQueryBuilder filterLevelQueryBuilder;
    private DocumentAllowList documentWhitelist;

    DlsFilterLevelActionHandler(String action, ActionRequest request, ActionListener<?> listener, EvaluatedDlsFlsConfig evaluatedDlsFlsConfig,
                                Resolved resolved, Client nodeClient, ClusterService clusterService, IndicesService indicesService,
                                IndexNameExpressionResolver resolver, DlsQueryParser dlsQueryParser, ThreadContext threadContext) {
        this.action = action;
        this.request = request;
        this.listener = listener;
        this.evaluatedDlsFlsConfig = evaluatedDlsFlsConfig;
        this.resolved = resolved;
        this.nodeClient = nodeClient;
        this.clusterService = clusterService;
        this.indicesService = indicesService;
        this.dlsQueryParser = dlsQueryParser;
        this.threadContext = threadContext;
        this.resolver = resolver;

        this.requiresIndexScoping = resolved.isLocalAll() || resolved.getAllIndicesResolved(clusterService, resolver).size() != 1;
    }

    private boolean handle() {

        try (StoredContext ctx = threadContext.newStoredContext(true)) {

            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE, request.toString());

            try {
                if (!createQueryExtension()) {
                    return true;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Created filterLevelQuery for " + request + ":\n" + filterLevelQueryBuilder);
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
                listener.onFailure(new OpenSearchSecurityException(
                        "Unsupported request type for filter level DLS: " + action + "; " + request.getClass().getName()));
                return false;
            }
        }
    }

    private boolean handle(SearchRequest searchRequest, StoredContext ctx) {
        if (documentWhitelist != null) {
            documentWhitelist.applyTo(threadContext);
        }

        String localClusterAlias = LOCAL_CLUSTER_ALIAS_GETTER.apply(searchRequest);

        if (localClusterAlias != null) {
            try {
                createQueryExtension(localClusterAlias);
            } catch (Exception e) {
                log.error("Unable to handle filter level DLS", e);
                listener.onFailure(new OpenSearchSecurityException("Unable to handle filter level DLS", e));
                return false;
            }
        }

        if (searchRequest.source().query() != null) {
            filterLevelQueryBuilder.must(searchRequest.source().query());
        }

        searchRequest.source().query(filterLevelQueryBuilder);

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

    private boolean handle(GetRequest getRequest, StoredContext ctx) {
        if (documentWhitelist != null) {
            documentWhitelist.applyTo(threadContext);
        }

        SearchRequest searchRequest = new SearchRequest(getRequest.indices());
        BoolQueryBuilder query = QueryBuilders.boolQuery().must(QueryBuilders.idsQuery().addIds(getRequest.id())).must(filterLevelQueryBuilder);
        searchRequest.source(SearchSourceBuilder.searchSource().query(query));

        nodeClient.search(searchRequest, new ActionListener<SearchResponse>() {
            @Override
            public void onResponse(SearchResponse response) {
                try {

                    ctx.restore();

                    long hits = response.getHits().getTotalHits().value;

                    @SuppressWarnings("unchecked")
                    ActionListener<GetResponse> getListener = (ActionListener<GetResponse>) listener;
                    if (hits == 1) {
                        getListener.onResponse(new GetResponse(searchHitToGetResult(response.getHits().getAt(0))));
                    } else if (hits == 0) {
                        getListener.onResponse(new GetResponse(new GetResult(searchRequest.indices()[0], "_doc", getRequest.id(),
                                SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, -1, false, null, null, null)));
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
        if (documentWhitelist != null) {
            documentWhitelist.applyTo(threadContext);
        }

        Map<String, Set<String>> idsGroupedByIndex = multiGetRequest.getItems().stream()
                .collect(Collectors.groupingBy((item) -> item.index(), Collectors.mapping((item) -> item.id(), Collectors.toSet())));
        Set<String> indices = idsGroupedByIndex.keySet();
        SearchRequest searchRequest = new SearchRequest(indices.toArray(new String[indices.size()]));

        BoolQueryBuilder query;

        if (indices.size() == 1) {
            Set<String> ids = idsGroupedByIndex.get(indices.iterator().next());
            query = QueryBuilders.boolQuery().must(QueryBuilders.idsQuery().addIds(ids.toArray(new String[ids.size()])))
                    .must(filterLevelQueryBuilder);
        } else {
            BoolQueryBuilder mgetQuery = QueryBuilders.boolQuery().minimumShouldMatch(1);

            for (Map.Entry<String, Set<String>> entry : idsGroupedByIndex.entrySet()) {
                BoolQueryBuilder indexQuery = QueryBuilders.boolQuery().must(QueryBuilders.termQuery("_index", entry.getKey()))
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
                    multiGetListener.onResponse(new MultiGetResponse(itemResponses.toArray(new MultiGetItemResponse[itemResponses.size()])));
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
        listener.onFailure(new OpenSearchSecurityException(
                "Filter-level DLS via cross cluster search is not available for scrolling and minimize_roundtrips=true"));
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
                    log.warn("Could not find IndexService for " + hit.getIndex() + "; assuming all fields as document fields."
                            + "This should not happen, however this should also not pose a big problem as ES mixes the fields again anyway.\n"
                            + "IndexMetadata: " + indexMetadata);
                }

                documentFields = fields;
                metadataFields = Collections.emptyMap();
            }
        }

        @SuppressWarnings("deprecation")
        String type = hit.getType();

        return new GetResult(hit.getIndex(), type, hit.getId(), hit.getSeqNo(), hit.getPrimaryTerm(), hit.getVersion(), true, hit.getSourceRef(),
                documentFields, metadataFields);
    }

    private boolean createQueryExtension() throws IOException {
        return createQueryExtension(null);
    }

    private boolean createQueryExtension(String localClusterAlias) throws IOException {
        Map<String, Set<String>> filterLevelQueries = evaluatedDlsFlsConfig.getDlsQueriesByIndex();

        BoolQueryBuilder dlsQueryBuilder = QueryBuilders.boolQuery().minimumShouldMatch(1);
        DocumentAllowList documentWhitelist = new DocumentAllowList();

        int queryCount = 0;

        Set<String> indices = resolved.getAllIndicesResolved(clusterService, resolver);

        for (String index : indices) {
            String dlsEval = SecurityUtils.evalMap(filterLevelQueries, index);

            String prefixedIndex;

            if (localClusterAlias != null) {
                prefixedIndex = localClusterAlias + ":" + index;
            } else {
                prefixedIndex = index;
            }

            if (dlsEval == null) {
                if (requiresIndexScoping) {
                    // This index has no DLS configured, thus it is unrestricted.
                    // To allow the index in a complex query, we need to add the query below to let the index pass.
                    dlsQueryBuilder.should(QueryBuilders.termQuery("_index", prefixedIndex));
                }
                continue;
            }

            Set<String> unparsedDlsQueries = filterLevelQueries.get(dlsEval);

            if (unparsedDlsQueries == null || unparsedDlsQueries.isEmpty()) {
                if (requiresIndexScoping) {
                    // This index has no DLS configured, thus it is unrestricted.
                    // To allow the index in a complex query, we need to add the query below to let the index pass.
                    dlsQueryBuilder.should(QueryBuilders.termQuery("_index", prefixedIndex));
                }
                continue;
            }

            for (String unparsedDlsQuery : unparsedDlsQueries) {
                queryCount++;

                QueryBuilder parsedDlsQuery = dlsQueryParser.parse(unparsedDlsQuery);

                if (!requiresIndexScoping) {
                    dlsQueryBuilder.should(parsedDlsQuery);
                } else {
                    // The original request referred to several indices. That's why we have to scope each query to the index it is meant for
                    dlsQueryBuilder.should(QueryBuilders.boolQuery().must(QueryBuilders.termQuery("_index", prefixedIndex)).must(parsedDlsQuery));
                }

                Set<QueryBuilder> queryBuilders = QueryBuilderTraverser.findAll(parsedDlsQuery,
                        (q) -> (q instanceof TermsQueryBuilder) && ((TermsQueryBuilder) q).termsLookup() != null);

                for (QueryBuilder queryBuilder : queryBuilders) {
                    TermsQueryBuilder termsQueryBuilder = (TermsQueryBuilder) queryBuilder;

                    documentWhitelist.add(termsQueryBuilder.termsLookup().index(), termsQueryBuilder.termsLookup().id());
                }
            }

        }

        if (queryCount == 0) {
            // Return false to indicate that no query manipulation is necessary
            return false;
        } else {
            this.filterLevelQueryBuilder = dlsQueryBuilder;
            this.documentWhitelist = documentWhitelist;
            return true;
        }
    }

}
