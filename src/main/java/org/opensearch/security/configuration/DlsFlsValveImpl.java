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

package org.opensearch.security.configuration;

import org.opensearch.rest.RestStatus;
import org.opensearch.security.support.SecurityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.BytesRef;

import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.StreamSupport;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.RealtimeRequest;
import org.opensearch.action.admin.indices.shrink.ResizeRequest;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.ParsedQuery;
import org.opensearch.search.DocValueFormat;
import org.opensearch.search.aggregations.BucketOrder;
import org.opensearch.search.aggregations.InternalAggregation;
import org.opensearch.search.aggregations.InternalAggregations;
import org.opensearch.search.aggregations.bucket.MultiBucketsAggregation.Bucket;
import org.opensearch.search.aggregations.bucket.terms.InternalTerms;
import org.opensearch.search.aggregations.bucket.terms.StringTerms;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.internal.SearchContext;
import org.opensearch.search.query.QuerySearchResult;
import org.opensearch.threadpool.ThreadPool;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;

import com.google.common.collect.ImmutableList;

public class DlsFlsValveImpl implements DlsFlsRequestValve {
    private static final Logger log = LogManager.getLogger(DlsFlsValveImpl.class);

    /**
     *
     * @param request
     * @param listener
     * @return false on error
     */
    public boolean invoke(final String action, final ActionRequest request, final ActionListener<?> listener,
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
                listener.onFailure(new OpenSearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated"));
                return false;
            }

            if(request instanceof BulkRequest) {
                for(DocWriteRequest<?> inner:((BulkRequest) request).requests()) {
                    if(inner instanceof UpdateRequest) {
                        listener.onFailure(new OpenSearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated"));
                        return false;
                    }
                }
            }

            if(request instanceof BulkShardRequest) {
                for(BulkItemRequest inner:((BulkShardRequest) request).items()) {
                    if(inner.request() instanceof UpdateRequest) {
                        listener.onFailure(new OpenSearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated"));
                        return false;
                    }
                }
            }

            if(request instanceof ResizeRequest) {
                listener.onFailure(new OpenSearchSecurityException("Resize is not supported when FLS or DLS or Fieldmasking is activated"));
                return false;
            }

            if(action.contains("plugins/replication")) {
                listener.onFailure(new OpenSearchSecurityException("Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated", RestStatus.FORBIDDEN));
                return false;
            }
        }

        if(dls) {
            if(request instanceof SearchRequest) {
                final SearchSourceBuilder source = ((SearchRequest)request).source();
                if(source != null) {

                    if(source.profile()) {
                        listener.onFailure(new OpenSearchSecurityException("Profiling is not supported when DLS is activated"));
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

            final String dlsEval = SecurityUtils.evalMap(queries, context.indexShard().indexSettings().getIndex().getName());

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
}
