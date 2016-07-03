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

import java.io.Closeable;
import java.util.concurrent.ConcurrentHashMap;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.IndexModule;
import org.elasticsearch.index.engine.Engine.Delete;
import org.elasticsearch.index.engine.Engine.Index;
import org.elasticsearch.index.shard.IndexEventListener;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.index.shard.IndexingOperationListener;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.support.ConfigConstants;

public class ConfigurationService extends AbstractLifecycleComponent<ConfigurationService> implements Closeable {

    private final IndexModule indexModule;
    private final Client client;
    private final ClusterService cs;
    private final AdminDNs adminDns ;
	private ThreadContext threadContext;

    @Inject
    public ConfigurationService(final ConfigurationLoader cl, final Settings settings, final IndexModule indexModule, final Client client,
            final ClusterService cs, AdminDNs adminDns, ThreadPool threadPool) {
        super(settings);
        this.indexModule = indexModule;
        this.client = client;
        this.cs = cs;
        this.adminDns = adminDns;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    protected void doStart() {
        this.indexModule.addIndexEventListener(new SearchGuardIndexEventListener());
    }

    @Override
    protected void doStop() {
    }

    @Override
    protected void doClose() {
    }

    
    private class SearchGuardIndexEventListener implements IndexEventListener {
        private final ConcurrentHashMap<ShardId, ConfigurationUpdateListener> listeners = new ConcurrentHashMap<ShardId, ConfigurationUpdateListener>();

        @Override
        public void afterIndexShardStarted(final IndexShard indexShard) {

            if (indexShard.routingEntry().primary() && indexShard.indexSettings().matchesIndexName("searchguard")) {
                final ConfigurationUpdateListener auditListener = new ConfigurationUpdateListener(indexShard);                
                ConfigurationService.this.indexModule.addIndexOperationListener(auditListener);
                listeners.put(indexShard.shardId(), auditListener);
                logger.debug("Listener for primary shard {} added", indexShard.shardId());
            }
        }

        @Override
        public void beforeIndexShardClosed(final ShardId shardId, final IndexShard indexShard, final Settings indexSettings) {
            final ConfigurationUpdateListener listener = listeners.remove(shardId);

            if (listener != null) {
            	// TODO 5.0: Cannot remove listener from IndexModule
                //indexShard.indexingService().removeListener(listener);
                logger.debug("Listener for shard {} removed", shardId);
            }
        };    	
    }
    
    // TODO 5.0: check usage
    private class ConfigurationUpdateListener implements IndexingOperationListener {

        // TODO 5.0: Unused?
        private final IndexShard indexShard;

        public ConfigurationUpdateListener(final IndexShard indexShard) {
            super();
            this.indexShard = indexShard;
        }

        @Override
        public Index preIndex(final Index index) {

            final BytesReference source = index.source();

            if (source == null || source.length() == 0) {
                throw new ElasticsearchException("empty source");
            }
            //TODO checkAdmin()??

            // for (final ConfigChangeListener configChangeListener :
            // listeners.get(index.type())) {
            // configChangeListener.validate(index.type(), toSettings(source));
            // }

            return index;
        }

        
        @Override
        public void postIndex(final Index index, boolean created) {
            callback(index);
        }


        @Override
        public Delete preDelete(Delete delete) {
            //checkAdmin();//TODO checkAdmin()??
        	return delete;
        }
        
        private void callback(final Index index) {
            final BytesReference source = index.source();

            if (source == null || source.length() == 0) {
                throw new ElasticsearchException("empty source");
            }
            
            if("auditlog".equals(index.type())) {
                return;
            }

            new Thread(new Runnable() {

                @Override
                public void run() {

                    try {
                        Thread.sleep(1200);
                    } catch (final InterruptedException e1) {
                        
                    }

                    logger.debug("Send a {} to all nodes", ConfigUpdateAction.NAME);
                    ConfigUpdateRequest cur = new ConfigUpdateRequest(new String[] { index.type() });
                    //cur.putInContext(ConfigConstants.SG_INTERNAL_REQUEST, Boolean.TRUE);
                    // TODO 5.0: Correct to put header on thread context here?
                    threadContext.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
                    client.execute(ConfigUpdateAction.INSTANCE, cur,
                            new ActionListener<ConfigUpdateResponse>() {

                                @Override
                                public void onResponse(final ConfigUpdateResponse response) {
                                    
                                }

                                @Override
                                public void onFailure(final Throwable e) {
                                    logger.error("Error config update request {}", e,e);
                                    //TODO retry? does cluster mngt. ensure this?
                                    //TODO make sure all nodes have current config in memory
                                
                                }
                            });
                }
            }).start();

        }
    }
    
    
}
