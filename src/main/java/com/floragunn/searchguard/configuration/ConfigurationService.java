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
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.engine.Engine.Create;
import org.elasticsearch.index.engine.Engine.Delete;
import org.elasticsearch.index.engine.Engine.Index;
import org.elasticsearch.index.indexing.IndexingOperationListener;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.indices.IndicesLifecycle;
import org.elasticsearch.indices.IndicesService;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.google.common.base.Strings;

public class ConfigurationService extends AbstractLifecycleComponent<ConfigurationService> implements Closeable {

    private final IndicesService is;
    private final Client client;
    private final ClusterService cs;
    private final AdminDNs adminDns ;

    @Inject
    public ConfigurationService(final ConfigurationLoader cl, final Settings settings, final IndicesService is, final Client client,
            final ClusterService cs, AdminDNs adminDns) {
        super(settings);
        this.is = is;
        this.client = client;
        this.cs = cs;
        this.adminDns = adminDns;
    }

    @Override
    protected void doStart() {
        this.is.indicesLifecycle().addListener(sgIndicesLsListener);
    }

    @Override
    protected void doStop() {
    }

    @Override
    protected void doClose() {
    }

    private final IndicesLifecycle.Listener sgIndicesLsListener = new IndicesLifecycle.Listener() {

        private final ConcurrentHashMap<ShardId, ConfigurationUpdateListener> listeners = new ConcurrentHashMap<ShardId, ConfigurationUpdateListener>();

        @Override
        public void afterIndexShardStarted(final IndexShard indexShard) {

            if (indexShard.routingEntry().primary() && indexShard.indexService().index().name().equals("searchguard")) {
                final ConfigurationUpdateListener auditListener = new ConfigurationUpdateListener(indexShard);
                indexShard.indexingService().addListener(auditListener);
                listeners.put(indexShard.shardId(), auditListener);
                logger.debug("Listener for primary shard {} added", indexShard.shardId());
            }
        }

        @Override
        public void beforeIndexShardClosed(final ShardId shardId, final IndexShard indexShard, final Settings indexSettings) {
            final ConfigurationUpdateListener listener = listeners.remove(shardId);

            if (listener != null) {
                indexShard.indexingService().removeListener(listener);
                logger.debug("Listener for shard {} removed", shardId);
            }
        };
    };

    private class ConfigurationUpdateListener extends IndexingOperationListener {

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

            return super.preIndex(index);
        }

        @Override
        public void postIndex(final Index index) {
            callback(index);
            super.postIndex(index);
        }

        @Override
        public void postIndexUnderLock(final Index index) {
            // callback(index);
            super.postIndexUnderLock(index);
        }

        @Override
        public Create preCreate(Create create) {
            //checkAdmin();//TODO checkAdmin()??
            return super.preCreate(create);
        }
        @Override
        public Delete preDelete(Delete delete) {
            //checkAdmin();//TODO checkAdmin()??
            return super.preDelete(delete);
        }
        private void callback(final Index index) {
            final BytesReference source = index.source();

            if (source == null || source.length() == 0) {
                throw new ElasticsearchException("empty source");
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
                    cur.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
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
