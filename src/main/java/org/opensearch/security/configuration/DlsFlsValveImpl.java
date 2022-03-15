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

import java.io.Serializable;
import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.StreamSupport;

import com.google.common.collect.ImmutableList;
import org.apache.lucene.search.BooleanClause.Occur;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.ConstantScoreQuery;
import org.apache.lucene.util.BytesRef;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.RealtimeRequest;
import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.opensearch.action.admin.indices.shrink.ResizeRequest;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Strings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.ParsedQuery;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.DocValueFormat;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.BucketOrder;
import org.opensearch.search.aggregations.InternalAggregation;
import org.opensearch.search.aggregations.InternalAggregations;
import org.opensearch.search.aggregations.bucket.MultiBucketsAggregation;
import org.opensearch.search.aggregations.bucket.sampler.DiversifiedAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.InternalTerms;
import org.opensearch.search.aggregations.bucket.terms.SignificantTermsAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.StringTerms;
import org.opensearch.search.aggregations.bucket.terms.StringTerms.Bucket;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.internal.SearchContext;
import org.opensearch.search.query.QuerySearchResult;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.securityconf.EvaluatedDlsFlsConfig;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.support.SecurityUtils;
import org.opensearch.threadpool.ThreadPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DlsFlsValveImpl implements DlsFlsRequestValve {

	private static final String MAP_EXECUTION_HINT = "map";
	private static final Logger log = LoggerFactory.getLogger(DlsFlsValveImpl.class);

    private final Client nodeClient;
    private final ClusterService clusterService;
    private final ThreadContext threadContext;
    private final Mode mode;
    private final DlsQueryParser dlsQueryParser;
    private final IndexNameExpressionResolver resolver;

    public DlsFlsValveImpl(Settings settings, Client nodeClient, ClusterService clusterService, IndexNameExpressionResolver resolver,
    		NamedXContentRegistry namedXContentRegistry, ThreadContext threadContext) {
        super();
        this.nodeClient = nodeClient;
        this.clusterService = clusterService;
        this.resolver = resolver;
        this.threadContext = threadContext;
        this.mode = Mode.get(settings);
        this.dlsQueryParser = new DlsQueryParser(namedXContentRegistry);
    }

    /**
     *
     * @param request
     * @param listener
     * @return false on error
     */
    public boolean invoke(String action, ActionRequest request, final ActionListener<?> listener, EvaluatedDlsFlsConfig evaluatedDlsFlsConfig,
            final Resolved resolved) {

        if (log.isDebugEnabled()) {
            log.debug("DlsFlsValveImpl.invoke()\nrequest: " + request + "\nevaluatedDlsFlsConfig: " + evaluatedDlsFlsConfig + "\nresolved: "
                    + resolved + "\nmode: " + mode);
        }

        if (evaluatedDlsFlsConfig == null || evaluatedDlsFlsConfig.isEmpty()) {
            return true;
        }

        if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE) != null) {
            if (log.isDebugEnabled()) {
                log.debug("DLS is already done for: " + threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE));
            }

            return true;
        }

        EvaluatedDlsFlsConfig filteredDlsFlsConfig = evaluatedDlsFlsConfig.filter(resolved);

        boolean doFilterLevelDls;

        if (mode == Mode.FILTER_LEVEL) {
            doFilterLevelDls = true;
        } else if (mode == Mode.LUCENE_LEVEL) {
            doFilterLevelDls = false;
        } else { // mode == Mode.ADAPTIVE
            Mode modeByHeader = getDlsModeHeader();

            if (modeByHeader == Mode.FILTER_LEVEL) {
                doFilterLevelDls = true;
                log.debug("Doing filter-level DLS due to header");
            } else {
                doFilterLevelDls = dlsQueryParser.containsTermLookupQuery(filteredDlsFlsConfig.getAllQueries());

                if (doFilterLevelDls) {
                    setDlsModeHeader(Mode.FILTER_LEVEL);
                    log.debug("Doing filter-level DLS because the query contains a TLQ");
                } else {
                    log.debug("Doing lucene-level DLS because the query does not contain a TLQ");
                }
            }
        }

        if (!doFilterLevelDls) {
            setDlsHeaders(evaluatedDlsFlsConfig, request);
        }

        setFlsHeaders(evaluatedDlsFlsConfig, request);

        if (filteredDlsFlsConfig.isEmpty()) {
            return true;
        }

        if (request instanceof RealtimeRequest) {
            ((RealtimeRequest) request).realtime(Boolean.FALSE);
        }

        if (request instanceof SearchRequest) {

            SearchRequest searchRequest = ((SearchRequest) request);

            //When we encounter a terms or sampler aggregation with masked fields activated we forcibly
            //need to switch off global ordinals because field masking can break ordering
            //https://www.elastic.co/guide/en/elasticsearch/reference/master/eager-global-ordinals.html#_avoiding_global_ordinal_loading
            if (evaluatedDlsFlsConfig.hasFieldMasking()) {

                if (searchRequest.source() != null && searchRequest.source().aggregations() != null) {
                    for (AggregationBuilder aggregationBuilder : searchRequest.source().aggregations().getAggregatorFactories()) {
                        if (aggregationBuilder instanceof TermsAggregationBuilder) {
                            ((TermsAggregationBuilder) aggregationBuilder).executionHint(MAP_EXECUTION_HINT);
                        }

                        if (aggregationBuilder instanceof SignificantTermsAggregationBuilder) {
                            ((SignificantTermsAggregationBuilder) aggregationBuilder).executionHint(MAP_EXECUTION_HINT);
                        }

                        if (aggregationBuilder instanceof DiversifiedAggregationBuilder) {
                            ((DiversifiedAggregationBuilder) aggregationBuilder).executionHint(MAP_EXECUTION_HINT);
                        }
                    }
                }
            }

            if (!evaluatedDlsFlsConfig.hasFls() && !evaluatedDlsFlsConfig.hasDls()
                    && searchRequest.source().aggregations() != null) {

                boolean cacheable = true;

                for (AggregationBuilder af : searchRequest.source().aggregations().getAggregatorFactories()) {

                    if (!af.getType().equals("cardinality") && !af.getType().equals("count")) {
                        cacheable = false;
                        continue;
                    }

                    StringBuilder sb = new StringBuilder();

                    if (searchRequest.source() != null) {
                        sb.append(Strings.toString(searchRequest.source()) + System.lineSeparator());
                    }

                    sb.append(Strings.toString(af) + System.lineSeparator());

                    LoggerFactory.getLogger("debuglogger").error(sb.toString());

                }

                if (!cacheable) {
                    searchRequest.requestCache(Boolean.FALSE);
                } else {
                	LoggerFactory.getLogger("debuglogger").error("Shard requestcache enabled for "
                            + (searchRequest.source() == null ? "<NULL>" : Strings.toString(searchRequest.source())));
                }

            } else {
                searchRequest.requestCache(Boolean.FALSE);
            }
        }

        if (request instanceof UpdateRequest) {
            listener.onFailure(new OpenSearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated"));
            return false;
        }

        if (request instanceof BulkRequest) {
            for (DocWriteRequest<?> inner : ((BulkRequest) request).requests()) {
                if (inner instanceof UpdateRequest) {
                    listener.onFailure(new OpenSearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated"));
                    return false;
                }
            }
        }

        if (request instanceof BulkShardRequest) {
            for (BulkItemRequest inner : ((BulkShardRequest) request).items()) {
                if (inner.request() instanceof UpdateRequest) {
                    listener.onFailure(new OpenSearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated"));
                    return false;
                }
            }
        }

        if (request instanceof ResizeRequest) {
            listener.onFailure(new OpenSearchSecurityException("Resize is not supported when FLS or DLS or Fieldmasking is activated"));
            return false;
        }

        if(action.contains("plugins/replication")) {
            listener.onFailure(new OpenSearchSecurityException("Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated",
                    RestStatus.FORBIDDEN));
            return false;
        }
        
        if (evaluatedDlsFlsConfig.hasDls()) {
            if (request instanceof SearchRequest) {

                final SearchSourceBuilder source = ((SearchRequest) request).source();
                if (source != null) {

                    if (source.profile()) {
                        listener.onFailure(new OpenSearchSecurityException("Profiling is not supported when DLS is activated"));
                        return false;
                    }

                }
            }
        }

        if (doFilterLevelDls && filteredDlsFlsConfig.hasDls()) {
            return DlsFilterLevelActionHandler.handle(action, request, listener, evaluatedDlsFlsConfig, resolved, nodeClient, clusterService,
            		OpenSearchSecurityPlugin.GuiceHolder.getIndicesService(), resolver, dlsQueryParser, threadContext);
        } else {
            return true;
        }
    }

    @Override
    public void handleSearchContext(SearchContext context, ThreadPool threadPool, NamedXContentRegistry namedXContentRegistry) {
        try {
            @SuppressWarnings("unchecked")
            final Map<String, Set<String>> queries = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadPool.getThreadContext(),
                    ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER);

            final String dlsEval = SecurityUtils.evalMap(queries, context.indexShard().indexSettings().getIndex().getName());

            if (dlsEval != null) {

                if (context.suggest() != null) {
                    return;
                }

                assert context.parsedQuery() != null;

                final Set<String> unparsedDlsQueries = queries.get(dlsEval);
                
                if (unparsedDlsQueries != null && !unparsedDlsQueries.isEmpty()) {
                    BooleanQuery.Builder queryBuilder = dlsQueryParser.parse(unparsedDlsQueries, context.getQueryShardContext(),
                            (q) -> new ConstantScoreQuery(q));

                    queryBuilder.add(context.parsedQuery().query(), Occur.MUST);

                    ParsedQuery dlsQuery = new ParsedQuery(queryBuilder.build());

                    if (dlsQuery != null) {
                        context.parsedQuery(dlsQuery);
                        context.preProcess(true);
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Error evaluating dls for a search query: " + e, e);
        }
    }

    @Override
    public void onQueryPhase(QuerySearchResult queryResult) {
        InternalAggregations aggregations = queryResult.aggregations().expand();
        assert aggregations != null;

        queryResult.aggregations(
                InternalAggregations.from(
                        StreamSupport.stream(aggregations.spliterator(), false)
                                .map(aggregation -> aggregateBuckets((InternalAggregation)aggregation))
                                .collect(ImmutableList.toImmutableList())
                )
        );
    }

    private static InternalAggregation aggregateBuckets(InternalAggregation aggregation) {
        if (aggregation instanceof StringTerms) {
            StringTerms stringTerms = (StringTerms) aggregation;
            List<Bucket> buckets = stringTerms.getBuckets();
            if (buckets.size() > 1) {
                buckets = mergeBuckets(buckets, StringTermsGetter.getReduceOrder(stringTerms).comparator());
                aggregation = stringTerms.create(buckets);
            }
        }
        return aggregation;
    }

    private static List<StringTerms.Bucket> mergeBuckets(List<StringTerms.Bucket> buckets, Comparator<MultiBucketsAggregation.Bucket> comparator) {
        if (log.isDebugEnabled()) {
            log.debug("Merging buckets: {}", buckets.stream().map(b -> b.getKeyAsString()).collect(ImmutableList.toImmutableList()));
        }
        buckets.sort(comparator);
        BucketMerger merger = new BucketMerger(comparator, buckets.size());
        buckets.stream().forEach(merger);
        buckets = merger.getBuckets();

        if (log.isDebugEnabled()) {
            log.debug("New buckets: {}", buckets.stream().map(b -> b.getKeyAsString()).collect(ImmutableList.toImmutableList()));
        }
        return buckets;
    }

    private void setDlsHeaders(EvaluatedDlsFlsConfig dlsFls, ActionRequest request) {
        if (!dlsFls.getDlsQueriesByIndex().isEmpty()) {
            Map<String, Set<String>> dlsQueries = dlsFls.getDlsQueriesByIndex();

            if (request instanceof ClusterSearchShardsRequest && HeaderHelper.isTrustedClusterRequest(threadContext)) {
                threadContext.addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, Base64Helper.serializeObject((Serializable) dlsQueries));
                if (log.isDebugEnabled()) {
                    log.debug("added response header for DLS info: {}", dlsQueries);
                }
            } else {
                if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER) != null) {
                    Object deserializedDlsQueries = Base64Helper.deserializeObject(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER));
                    if (!dlsQueries.equals(deserializedDlsQueries)) {                        
                        throw new OpenSearchSecurityException(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER + " does not match (SG 900D)");
                    }
                } else {
                    threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, Base64Helper.serializeObject((Serializable) dlsQueries));
                    if (log.isDebugEnabled()) {
                        log.debug("attach DLS info: {}", dlsQueries);
                    }
                }
            }
        }
    }

    private void setDlsModeHeader(Mode mode) {
        String modeString = mode.name();

        if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER) != null) {
            if (!modeString.equals(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER))) {
                log.warn("Cannot update DLS mode to " + mode + "; current: " + threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER));
            }
        } else {
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER, modeString);
        }
    }

    private Mode getDlsModeHeader() {
        String modeString = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER);

        if (modeString != null) {
            return Mode.valueOf(modeString);
        } else {
            return null;
        }
    }

    private void setFlsHeaders(EvaluatedDlsFlsConfig dlsFls, ActionRequest request) {
        if (!dlsFls.getFieldMaskingByIndex().isEmpty()) {
            Map<String, Set<String>> maskedFieldsMap = dlsFls.getFieldMaskingByIndex();

            if (request instanceof ClusterSearchShardsRequest && HeaderHelper.isTrustedClusterRequest(threadContext)) {
                threadContext.addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, Base64Helper.serializeObject((Serializable) maskedFieldsMap));
                if (log.isDebugEnabled()) {
                    log.debug("added response header for masked fields info: {}", maskedFieldsMap);
                }
            } else {

                if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER) != null) {
                    if (!maskedFieldsMap.equals(Base64Helper.deserializeObject(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER)))) {
                        throw new OpenSearchSecurityException(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER + " does not match (SG 901D)");
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER + " already set");
                        }
                    }
                } else {
                    threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, Base64Helper.serializeObject((Serializable) maskedFieldsMap));
                    if (log.isDebugEnabled()) {
                        log.debug("attach masked fields info: {}", maskedFieldsMap);
                    }
                }
            }
        }

        if (!dlsFls.getFlsByIndex().isEmpty()) {
            Map<String, Set<String>> flsFields = dlsFls.getFlsByIndex();

            if (request instanceof ClusterSearchShardsRequest && HeaderHelper.isTrustedClusterRequest(threadContext)) {
                threadContext.addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, Base64Helper.serializeObject((Serializable) flsFields));
                if (log.isDebugEnabled()) {
                    log.debug("added response header for FLS info: {}", flsFields);
                }
            } else {
                if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER) != null) {
                    if (!flsFields.equals(Base64Helper.deserializeObject(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER)))) {
                        throw new OpenSearchSecurityException(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER + " does not match (SG 901D) " + flsFields
                                + "---" + Base64Helper.deserializeObject(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER)));
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER + " already set");
                        }
                    }
                } else {
                    threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, Base64Helper.serializeObject((Serializable) flsFields));
                    if (log.isDebugEnabled()) {
                        log.debug("attach FLS info: {}", flsFields);
                    }
                }
            }

        }
    }

    private static class BucketMerger implements Consumer<Bucket> {
        private Comparator<MultiBucketsAggregation.Bucket> comparator;
        private StringTerms.Bucket bucket = null;
        private int mergeCount;
        private long mergedDocCount;
        private long mergedDocCountError;
        private boolean showDocCountError = true;
        private final ImmutableList.Builder<StringTerms.Bucket> builder;

        BucketMerger(Comparator<MultiBucketsAggregation.Bucket> comparator, int size) {
            this.comparator = Objects.requireNonNull(comparator);
            builder = ImmutableList.builderWithExpectedSize(size);
        }

        private void finalizeBucket() {
            if (mergeCount == 1) {
                builder.add(this.bucket);
            } else {
                builder.add(new StringTerms.Bucket(StringTermsGetter.getTerm(bucket), mergedDocCount,
                        (InternalAggregations) bucket.getAggregations(), showDocCountError, mergedDocCountError,
                        StringTermsGetter.getDocValueFormat(bucket)));
            }
        }

        private void merge(StringTerms.Bucket bucket) {
            if (this.bucket != null && (bucket == null || comparator.compare(this.bucket, bucket) != 0)) {
                finalizeBucket();
                this.bucket = null;
                mergeCount = 0;
                mergedDocCount = 0;
                mergedDocCountError = 0;
                showDocCountError = true;
            }
        }

        public List<StringTerms.Bucket> getBuckets() {
            merge(null);
            return builder.build();
        }

        @Override
        public void accept(StringTerms.Bucket bucket) {
            merge(bucket);
            mergeCount++;
            mergedDocCount += bucket.getDocCount();
            if (showDocCountError) {
                try {
                    mergedDocCountError += bucket.getDocCountError();
                } catch (IllegalStateException e) {
                    showDocCountError = false;
                }
            }
            this.bucket = bucket;
        }
    }

    private static class StringTermsGetter {
        private static final Field REDUCE_ORDER = getField(InternalTerms.class, "reduceOrder");
        private static final Field TERM_BYTES = getField(StringTerms.Bucket.class, "termBytes");
        private static final Field FORMAT = getField(InternalTerms.Bucket.class, "format");

        private StringTermsGetter() {
        }

        private static <T> Field getFieldPrivileged(Class<T> cls, String name) {
            try {
                final Field field = cls.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException | SecurityException e) {
                log.error("Failed to get class {} declared field {}", cls.getSimpleName(), name, e);
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    throw new RuntimeException(e);
                }
            }
        }

        private static <T> Field getField(Class<T> cls, String name) {
            SpecialPermission.check();
            return AccessController.doPrivileged((PrivilegedAction<Field>) () -> getFieldPrivileged(cls, name));
        }

        private static <T, C> T getFieldValue(Field field, C c) {
            try {
                return (T)field.get(c);
            } catch (IllegalArgumentException | IllegalAccessException e) {
                log.error("Exception while getting value {} of class {}", field.getName(), c.getClass().getSimpleName(), e);
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    throw new RuntimeException(e);
                }
            }
        }

        public static BucketOrder getReduceOrder(StringTerms stringTerms) {
            return getFieldValue(REDUCE_ORDER, stringTerms);
        }

        public static BytesRef getTerm(StringTerms.Bucket bucket) {
            return getFieldValue(TERM_BYTES, bucket);
        }

        public static DocValueFormat getDocValueFormat(StringTerms.Bucket bucket) {
            return getFieldValue(FORMAT, bucket);
        }
    }

    public static enum Mode {
        ADAPTIVE, LUCENE_LEVEL, FILTER_LEVEL;

        static Mode get(Settings settings) {
            String modeString = settings.get(ConfigConstants.SECURITY_DLS_MODE);

            if ("adaptive".equalsIgnoreCase(modeString)) {
                return Mode.ADAPTIVE;
            } else if ("lucene_level".equalsIgnoreCase(modeString)) {
                return Mode.LUCENE_LEVEL;
            } else if ("filter_level".equalsIgnoreCase(modeString)) {
                return Mode.FILTER_LEVEL;
            } else {
                return Mode.ADAPTIVE;
            }
        }
    }
}

