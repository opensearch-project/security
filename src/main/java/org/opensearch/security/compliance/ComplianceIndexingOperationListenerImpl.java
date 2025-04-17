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

package org.opensearch.security.compliance;

import java.util.Arrays;
import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchRequestBuilder;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.IndexService;
import org.opensearch.index.engine.Engine.Delete;
import org.opensearch.index.engine.Engine.DeleteResult;
import org.opensearch.index.engine.Engine.Index;
import org.opensearch.index.engine.Engine.IndexResult;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.shard.IndexShard;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER;

public final class ComplianceIndexingOperationListenerImpl extends ComplianceIndexingOperationListener {

    private static final Logger log = LogManager.getLogger(ComplianceIndexingOperationListenerImpl.class);
    private final AuditLog auditlog;
    private final ThreadPool threadPool;
    private final Client client;
    private volatile IndexService is;

    public ComplianceIndexingOperationListenerImpl(final AuditLog auditlog, final ThreadPool threadPool, final Client client) {
        super();
        this.auditlog = auditlog;
        this.threadPool = threadPool;
        this.client = client;
    }

    @Override
    public void setIs(final IndexService is) {
        if (this.is != null) {
            throw new OpenSearchException("Index service already set");
        }
        this.is = is;
    }

    private static final class Context {
        private final GetResponse getResponse;

        public Context(GetResponse getResponse) {
            super();
            this.getResponse = getResponse;
        }

        public GetResponse getGetResponse() {
            return getResponse;
        }
    }

    private static final ThreadLocal<Context> threadContext = new ThreadLocal<Context>();

    @Override
    public void postDelete(final ShardId shardId, final Delete delete, final DeleteResult result) {
        final ComplianceConfig complianceConfig = auditlog.getComplianceConfig();
        if (isLoggingWriteEnabled(complianceConfig, shardId.getIndexName())) {
            Objects.requireNonNull(is);
            if (result.getFailure() == null
                && result.isFound()
                && delete.origin() == org.opensearch.index.engine.Engine.Operation.Origin.PRIMARY) {
                auditlog.logDocumentDeleted(shardId, delete, result);
            }
        }
    }

    @Override
    public Index preIndex(final ShardId shardId, final Index index) {
        if (isLoggingWriteDiffEnabled(auditlog.getComplianceConfig(), shardId.getIndexName())) {
            Objects.requireNonNull(is);

            final IndexShard shard;

            if (index.origin() != org.opensearch.index.engine.Engine.Operation.Origin.PRIMARY) {
                return index;
            }

            if ((shard = is.getShardOrNull(shardId.getId())) == null) {
                return index;
            }

            if (shard.isReadAllowed()) {
                try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
                    threadPool.getThreadContext().putTransient(OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, true);
                    System.out.println("index.id(): " + index.id());
                    System.out.println("index.getIfSeqNo(): " + index.getIfSeqNo());
                    System.out.println("index.getIfPrimaryTerm(): " + index.getIfPrimaryTerm());

                    System.out.println("doc stats: " + shard.docStats().getCount());
//                    GetRequest getRequest = new GetRequest(shardId.getIndexName());
//                    getRequest.id(index.id());
//                    getRequest.refresh(true);
//                    getRequest.realtime(true);
//                    client.get(getRequest, ActionListener.wrap(r -> {
//                        System.out.println("index name: " + shardId.getIndexName());
//                        System.out.println("doc id: " + index.id());
//                        System.out.println("r.isExists(): " + r.isExists());
//                        System.out.println("r: " + r.getSourceAsString());
//                        if (r.isExists()) {
//                            threadContext.set(new Context(r));
//                        } else {
//                            threadContext.set(new Context(null));
//                        }
//                    }, fr -> {
//                        if (log.isDebugEnabled()) {
//                            log.debug("Cannot retrieve original document due to {}", fr.getMessage());
//                            log.debug("Cannot read from shard {}", shardId);
//                        }
//                    }));
                    SearchRequest searchRequest = new SearchRequest(".opendistro_security");
                    // TODO make this a match all request
                    SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                    sourceBuilder.query(QueryBuilders.matchAllQuery());
                    searchRequest.source(sourceBuilder);
                    searchRequest.indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN_HIDDEN);
                    client.search(searchRequest, ActionListener.wrap(r -> {
                        System.out.println("index name: " + shardId.getIndexName());
                        System.out.println("doc id: " + index.id());
                        System.out.println("hits: " + Arrays.toString(r.getHits().getHits()));
                        threadContext.set(new Context(null));
                    }, fr -> {
                        if (log.isDebugEnabled()) {
                            log.debug("Cannot retrieve original document due to {}", fr.getMessage());
                            log.debug("Cannot read from shard {}", shardId);
                        }
                    }));
                } catch (Exception e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Cannot retrieve original document due to {}", e.toString());
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Cannot read from shard {}", shardId);
                }
            }
        }

        return index;
    }

    @Override
    public void postIndex(final ShardId shardId, final Index index, final Exception ex) {
        if (isLoggingWriteDiffEnabled(auditlog.getComplianceConfig(), shardId.getIndexName())) {
            threadContext.remove();
        }
    }

    @Override
    public void postIndex(ShardId shardId, Index index, IndexResult result) {
        final ComplianceConfig complianceConfig = auditlog.getComplianceConfig();
        if (!isLoggingWriteEnabled(complianceConfig, shardId.getIndexName())) {
            return;
        }

        if (complianceConfig.shouldLogDiffsForWrite()) {
            final Context context = threadContext.get();
            final GetResponse previousContent = context == null ? null : context.getGetResponse();
            threadContext.remove();
            Objects.requireNonNull(is);

            if (result.getFailure() != null || index.origin() != org.opensearch.index.engine.Engine.Operation.Origin.PRIMARY) {
                return;
            }

            if (is.getShardOrNull(shardId.getId()) == null) {
                return;
            }

            if (previousContent == null) {
                // no previous content
                if (!result.isCreated()) {
                    log.warn(
                        "No previous content and not created (its an update but do not find orig source) for {}/{}/{}",
                        index.startTime(),
                        shardId,
                        index.id()
                    );
                }
                assert result.isCreated() : "No previous content and not created";
            } else {
                if (result.isCreated()) {
                    log.warn("Previous content and created for {}/{}/{}", index.startTime(), shardId, index.id());
                }
                assert !result.isCreated() : "Previous content and created";
            }

            auditlog.logDocumentWritten(shardId, previousContent, index, result);
        } else {
            // no diffs
            if (result.getFailure() != null || index.origin() != org.opensearch.index.engine.Engine.Operation.Origin.PRIMARY) {
                return;
            }

            auditlog.logDocumentWritten(shardId, null, index, result);
        }
    }

    private static boolean isLoggingWriteEnabled(final ComplianceConfig complianceConfig, final String indexName) {
        return complianceConfig != null && complianceConfig.writeHistoryEnabledForIndex(indexName);
    }

    private static boolean isLoggingWriteDiffEnabled(final ComplianceConfig complianceConfig, final String indexName) {
        return isLoggingWriteEnabled(complianceConfig, indexName) && complianceConfig.shouldLogDiffsForWrite();
    }
}
