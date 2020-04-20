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

package com.amazon.opendistroforelasticsearch.security.compliance;

import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.engine.Engine.Delete;
import org.elasticsearch.index.engine.Engine.DeleteResult;
import org.elasticsearch.index.engine.Engine.Index;
import org.elasticsearch.index.engine.Engine.IndexResult;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.index.shard.ShardId;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;

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
            throw new ElasticsearchException("Index service already set");
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
        if (auditlog.getComplianceConfig().isEnabled()) {
            Objects.requireNonNull(is);
            if(result.getFailure() == null && result.isFound() && delete.origin() == org.elasticsearch.index.engine.Engine.Operation.Origin.PRIMARY) {
                auditlog.logDocumentDeleted(shardId, delete, result);
            }
        }
    }

    @Override
    public Index preIndex(final ShardId shardId, final Index index) {
        final ComplianceConfig complianceConfig = auditlog.getComplianceConfig();
        if (complianceConfig.isEnabled() && complianceConfig.shouldLogDiffsForWrite()) {
            Objects.requireNonNull(is);

            final IndexShard shard;

            if (index.origin() != org.elasticsearch.index.engine.Engine.Operation.Origin.PRIMARY) {
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
        final ComplianceConfig complianceConfig = auditlog.getComplianceConfig();
        if (complianceConfig.isEnabled() && complianceConfig.shouldLogDiffsForWrite()) {
            threadContext.remove();
        }
    }

    @Override
    public void postIndex(ShardId shardId, Index index, IndexResult result) {
        final ComplianceConfig complianceConfig = auditlog.getComplianceConfig();
        if (complianceConfig.isEnabled() && complianceConfig.shouldLogDiffsForWrite()) {
            final Context context = threadContext.get();
            final GetResult previousContent = context==null?null:context.getGetResult();
            threadContext.remove();
            Objects.requireNonNull(is);

            if (result.getFailure() != null || index.origin() != org.elasticsearch.index.engine.Engine.Operation.Origin.PRIMARY) {
                return;
            }

            if(is.getShardOrNull(shardId.getId()) == null) {
                return;
            }

            if(previousContent == null) {
                //no previous content
                if(!result.isCreated()) {
                    log.warn("No previous content and not created (its an update but do not find orig source) for {}", index.startTime()+"/"+shardId+"/"+index.type()+"/"+index.id());
                }
                assert result.isCreated():"No previous content and not created";
            } else {
                if(result.isCreated()) {
                    log.warn("Previous content and created for {}",index.startTime()+"/"+shardId+"/"+index.type()+"/"+index.id());
                }
                assert !result.isCreated():"Previous content and created";
            }

            auditlog.logDocumentWritten(shardId, previousContent, index, result);
        } else if (complianceConfig.isEnabled()) {
            //no diffs
            if (result.getFailure() != null || index.origin() != org.elasticsearch.index.engine.Engine.Operation.Origin.PRIMARY) {
                return;
            }

            auditlog.logDocumentWritten(shardId, null, index, result);
        }
    }

}
