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
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.engine.EngineConfig;
import org.elasticsearch.index.engine.EngineException;
import org.elasticsearch.index.engine.IndexSearcherWrapper;
import org.elasticsearch.index.shard.AbstractIndexShardComponent;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.indices.IndicesLifecycle;
import org.elasticsearch.indices.IndicesLifecycle.Listener;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.user.User;

public class SearchGuardIndexSearcherWrapper extends AbstractIndexShardComponent implements IndexSearcherWrapper {

    private final AdminDNs admindns;
    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private volatile boolean shardReady;

    @Inject
    public SearchGuardIndexSearcherWrapper(final ShardId shardId, final IndicesLifecycle indicesLifecycle, final Settings indexSettings,
            final AdminDNs admindns) {
        super(shardId, indexSettings);
        this.admindns = admindns;
        
        if(!isSearchGuardIndexRequest()) {
            indicesLifecycle.addListener(new Listener() {

                @Override
                public void afterIndexShardPostRecovery(IndexShard indexShard) {
                    if(shardId.equals(indexShard.shardId())) {
                        shardReady = true;
                    }
                }
                
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
    public final IndexSearcher wrap(final EngineConfig engineConfig, final IndexSearcher searcher) throws EngineException {

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
                return dlsFlsWrap(engineConfig, searcher);
            //}
        }

        return searcher;
    }

    protected IndexSearcher dlsFlsWrap(final EngineConfig engineConfig, final IndexSearcher searcher) throws EngineException {
        return searcher;
    }

    protected DirectoryReader dlsFlsWrap(final DirectoryReader reader) throws IOException {
        return reader;
    }

    protected final boolean isAdminAuhtenticatedOrInternalRequest() {
        final RequestHolder current = RequestHolder.current();

        if (current != null) {
            final TransportRequest request = current.getRequest();

            if (request != null) {

                final User user = (User) request.getFromContext(ConfigConstants.SG_USER);

                if (user != null && admindns.isAdmin(user.getName())) {
                    return true;
                }

                if ("true".equals(HeaderHelper.getSafeFromHeader(request, ConfigConstants.SG_CONF_REQUEST_HEADER))) {
                    return true;
                }
            }
        }

        return false;
    }

    protected final boolean isSearchGuardIndexRequest() {
        return shardId.index().getName().equals("searchguard");
    }
}
