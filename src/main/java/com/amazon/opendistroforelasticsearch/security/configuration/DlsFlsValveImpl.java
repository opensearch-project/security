/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.configuration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.StreamSupport;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.admin.indices.shrink.ResizeRequest;
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.index.query.ParsedQuery;
import org.elasticsearch.search.aggregations.InternalAggregation;
import org.elasticsearch.search.aggregations.InternalAggregations;
import org.elasticsearch.search.aggregations.bucket.MultiBucketsAggregation.Bucket;
import org.elasticsearch.search.aggregations.bucket.terms.StringTermsGetter;
import org.elasticsearch.search.aggregations.bucket.terms.StringTerms;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.internal.SearchContext;
import org.elasticsearch.search.query.QuerySearchResult;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.HeaderHelper;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityUtils;

import com.google.common.collect.ImmutableList;

public class DlsFlsValveImpl implements DlsFlsRequestValve {
    private static final Logger log = LogManager.getLogger(DlsFlsValveImpl.class);

    /**
     *
     * @param request
     * @param listener
     * @return false on error
     */
    public boolean invoke(final ActionRequest request, final ActionListener<?> listener,
            final Map<String,Set<String>> allowedFlsFields,
            final Map<String,Set<String>> maskedFields,
            final Map<String,Set<String>> queries) {

        final boolean fls = allowedFlsFields != null && !allowedFlsFields.isEmpty();
        final boolean masked = maskedFields != null && !maskedFields.isEmpty();
        final boolean dls = queries != null && !queries.isEmpty();

        if(fls || masked || dls) {

            if(request instanceof RealtimeRequest) {
                ((RealtimeRequest) request).realtime(Boolean.FALSE);
            }

            if(request instanceof SearchRequest) {
                ((SearchRequest)request).requestCache(Boolean.FALSE);
            }

            if(request instanceof UpdateRequest) {
                listener.onFailure(new ElasticsearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated"));
                return false;
            }

            if(request instanceof BulkRequest) {
                for(DocWriteRequest<?> inner:((BulkRequest) request).requests()) {
                    if(inner instanceof UpdateRequest) {
                        listener.onFailure(new ElasticsearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated"));
                        return false;
                    }
                }
            }

            if(request instanceof BulkShardRequest) {
                for(BulkItemRequest inner:((BulkShardRequest) request).items()) {
                    if(inner.request() instanceof UpdateRequest) {
                        listener.onFailure(new ElasticsearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated"));
                        return false;
                    }
                }
            }

            if(request instanceof ResizeRequest) {
                listener.onFailure(new ElasticsearchSecurityException("Resize is not supported when FLS or DLS or Fieldmasking is activated"));
                return false;
            }
        }

        if(dls) {
            if(request instanceof SearchRequest) {
                final SearchSourceBuilder source = ((SearchRequest)request).source();
                if(source != null) {

                    if(source.profile()) {
                        listener.onFailure(new ElasticsearchSecurityException("Profiling is not supported when DLS is activated"));
                        return false;
                    }
                }
            }
        }

        return true;
    }

    @Override
    public void handleSearchContext(SearchContext context, ThreadPool threadPool, NamedXContentRegistry namedXContentRegistry) {
        try {
            final Map<String, Set<String>> queries = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadPool.getThreadContext(),
                    ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER);

            final String dlsEval = OpenDistroSecurityUtils.evalMap(queries, context.indexShard().indexSettings().getIndex().getName());

            if (dlsEval != null) {

                if(context.suggest() != null) {
                    return;
                }

                assert context.parsedQuery() != null;

                final Set<String> unparsedDlsQueries = queries.get(dlsEval);
                if (unparsedDlsQueries != null && !unparsedDlsQueries.isEmpty()) {
                    final ParsedQuery dlsQuery = DlsQueryParser.parse(unparsedDlsQueries, context.parsedQuery(), context.getQueryShardContext(), namedXContentRegistry);
                    context.parsedQuery(dlsQuery);
                    context.preProcess(true);
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
            List<StringTerms.Bucket> buckets = stringTerms.getBuckets();
            if (buckets.size() > 1) {
                buckets = mergeBuckets(buckets, StringTermsGetter.getReduceOrder(stringTerms).comparator());
                aggregation = stringTerms.create(buckets);
            }
        }
        return aggregation;
    }

    private static List<StringTerms.Bucket> mergeBuckets(List<StringTerms.Bucket> buckets, Comparator<Bucket> comparator) {
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

    private static class BucketMerger implements Consumer<StringTerms.Bucket> {
        private Comparator<Bucket> comparator;
        private StringTerms.Bucket bucket = null;
        private int mergeCount;
        private long mergedDocCount;
        private long mergedDocCountError;
        private boolean showDocCountError = true;
        private final ImmutableList.Builder<StringTerms.Bucket> builder;

        BucketMerger(Comparator<Bucket> comparator, int size) {
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
}
