/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.configuration;

import java.io.IOException;

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.search.IndexSearcher;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.engine.EngineConfig;
import org.elasticsearch.index.engine.EngineException;
import org.elasticsearch.index.shard.IndexEventListener;
import org.elasticsearch.index.shard.IndexSearcherWrapper;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.index.IndexModule;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.user.User;

public class SearchGuardIndexSearcherWrapper extends IndexSearcherWrapper {

    private final AdminDNs admindns;
    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private volatile boolean shardReady;
	private final ThreadContext threadContext;
	private final ShardId shardId;
	
    @Inject
    public SearchGuardIndexSearcherWrapper(final ShardId shardId, final IndexModule indexModule, final Settings indexSettings,
            final AdminDNs admindns, final ThreadPool threadPool) {
        super();
        this.admindns = admindns;
        this.shardId = shardId;
        this.threadContext = threadPool.getThreadContext();
        if(!isSearchGuardIndexRequest()) {
        	indexModule.addIndexEventListener(new IndexEventListener() {
        		// TODO 5.0: The following callback does not exist anymore
//                @Override
//                public void afterIndexShardPostRecovery(IndexShard indexShard) {
//                    if(shardId.equals(indexShard.shardId())) {
//                        shardReady = true;
//                    }
//                }
			});
        } else {
            shardReady = true;
        }
    }

    @Override
    public final DirectoryReader wrap(final DirectoryReader reader) throws IOException {

        if (log.isTraceEnabled()) {
            log.trace("DirectoryReader {} should be wrapped", reader.getClass());
        }
        
        if(!shardReady) {
            return reader;
        }

        if (!isAdminAuhtenticatedOrInternalRequest()) {

            //if (settings == null || settings.getAsBoolean("searchguard.dynamic.dlsfls_enabled", true)) {
                return dlsFlsWrap(reader);
            //}
        }

        return reader;

    }

    @Override
    public final IndexSearcher wrap(final IndexSearcher searcher) throws EngineException {

    	if (log.isTraceEnabled()) {
            log.trace("IndexSearcher {} should be wrapped (reader is {})", searcher.getClass(), searcher.getIndexReader().getClass());
        }

        if(!shardReady) {
            return searcher;
        }
        
        if (isSearchGuardIndexRequest() && !isAdminAuhtenticatedOrInternalRequest()) {
            return new IndexSearcher(new EmptyReader());
        }

        if (!isAdminAuhtenticatedOrInternalRequest()) {

            //if (settings == null || settings.getAsBoolean("searchguard.dynamic.dlsfls_enabled", true)) {
                return dlsFlsWrap(searcher);
            //}
        }

        return searcher;
    }

    protected IndexSearcher dlsFlsWrap(final IndexSearcher searcher) throws EngineException {
        return searcher;
    }

    protected DirectoryReader dlsFlsWrap(final DirectoryReader reader) throws IOException {
        return reader;
    }

    protected final boolean isAdminAuhtenticatedOrInternalRequest() {
    	// TODO 5.0: Is class RequestHolder still needed? Means, is it mandatory to skip this check if we do not have a current request?
    	final RequestHolder current = RequestHolder.current();

        if (current != null) {
            final TransportRequest request = current.getRequest();

            if (request != null) {

                final User user = (User) threadContext.getTransient(ConfigConstants.SG_USER);

                if (user != null && admindns.isAdmin(user.getName())) {
                    return true;
                }

                if ("true".equals(HeaderHelper.getSafeFromHeader(threadContext, request, ConfigConstants.SG_CONF_REQUEST_HEADER))) {
                    return true;
                }
            }
        }

        return false;
    }

    protected final boolean isSearchGuardIndexRequest() {
        return shardId.getIndexName().equals("searchguard");
    }
}
