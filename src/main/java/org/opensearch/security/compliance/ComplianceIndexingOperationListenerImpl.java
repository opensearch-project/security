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

package org.opensearch.security.compliance;

import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.index.IndexService;
import org.opensearch.index.engine.Engine.Delete;
import org.opensearch.index.engine.Engine.DeleteResult;
import org.opensearch.index.engine.Engine.Index;
import org.opensearch.index.engine.Engine.IndexResult;
import org.opensearch.index.get.GetResult;
import org.opensearch.index.shard.IndexShard;
import org.opensearch.index.shard.ShardId;

import org.opensearch.security.auditlog.AuditLog;

public final class ComplianceIndexingOperationListenerImpl extends ComplianceIndexingOperationListener {

    private static final Logger log = LogManager.getLogger(ComplianceIndexingOperationListenerImpl.class);
    private final AuditLog auditlog;
    private volatile IndexService is;

    public ComplianceIndexingOperationListenerImpl(final AuditLog auditlog) {
        super();
        this.auditlog = auditlog;
    }

    @Override
    public void setIs(final IndexService is) {
        if(this.is != null) {
            throw new OpenSearchException("Index service already set");
        }
        this.is = is;
    }

    private static final class Context {
        private final GetResult getResult;

        public Context(GetResult getResult) {
            super();
            this.getResult = getResult;
        }

        public GetResult getGetResult() {
            return getResult;
        }
    }

    private static final ThreadLocal<Context> threadContext = new ThreadLocal<Context>();

    @Override
    public void postDelete(final ShardId shardId, final Delete delete, final DeleteResult result) {
        final ComplianceConfig complianceConfig = auditlog.getComplianceConfig();
        if (isLoggingWriteEnabled(complianceConfig, shardId.getIndexName())) {
            Objects.requireNonNull(is);
            if(result.getFailure() == null && result.isFound() && delete.origin() == org.opensearch.index.engine.Engine.Operation.Origin.PRIMARY) {
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

            if((shard = is.getShardOrNull(shardId.getId())) == null) {
                return index;
            }

            if (shard.isReadAllowed()) {
                try {

                    final GetResult getResult = shard.getService().getForUpdate(index.type(), index.id(),
                            index.getIfSeqNo(), index.getIfPrimaryTerm());

                    if (getResult.isExists()) {
                        threadContext.set(new Context(getResult));
                    } else {
                        threadContext.set(new Context(null));
                    }
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
            final GetResult previousContent = context==null?null:context.getGetResult();
            threadContext.remove();
            Objects.requireNonNull(is);

            if (result.getFailure() != null || index.origin() != org.opensearch.index.engine.Engine.Operation.Origin.PRIMARY) {
                return;
            }

            if(is.getShardOrNull(shardId.getId()) == null) {
                return;
            }

            if(previousContent == null) {
                //no previous content
                if(!result.isCreated()) {
                    log.warn("No previous content and not created (its an update but do not find orig source) for {}/{}/{}/{}", index.startTime(), shardId, index.type(), index.id());
                }
                assert result.isCreated():"No previous content and not created";
            } else {
                if(result.isCreated()) {
                    log.warn("Previous content and created for {}/{}/{}/{}", index.startTime(), shardId, index.type(), index.id());
                }
                assert !result.isCreated():"Previous content and created";
            }

            auditlog.logDocumentWritten(shardId, previousContent, index, result);
        } else {
            //no diffs
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
