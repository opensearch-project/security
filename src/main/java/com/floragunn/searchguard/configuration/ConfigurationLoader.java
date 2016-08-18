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
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.get.MultiGetItemResponse;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.loader.JsonSettingsLoader;
import org.elasticsearch.common.util.concurrent.EsRejectedExecutionException;
import org.elasticsearch.common.xcontent.XContentHelper;

import com.floragunn.searchguard.support.ConfigConstants;

public class ConfigurationLoader {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Provider<Client> client;

    @Inject
    public ConfigurationLoader(final Provider<Client> client) {
        super();
        this.client = client;
    }

    public Map<String, Settings> load(final String[] events) {

        try {
            IndicesExistsRequest ier = new IndicesExistsRequest("searchguard");
            ier.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
            client.get().admin().indices().exists(ier, new ActionListener<IndicesExistsResponse>() {

                @Override
                public void onResponse(IndicesExistsResponse response) {
                    if(response != null && response.isExists()) {
                        log.debug("searchguard index exists");
                    } else {
                        log.debug("searchguard index doe not exist");
                    }               
                }

                @Override
                public void onFailure(Throwable e) {
                    
                    if(e instanceof EsRejectedExecutionException) {
                        log.debug("Unexpected exception while checking if searchguard index exists: {}", e.toString());       
                    } else {
                        log.warn("Unexpected exception while checking if searchguard index exists: {}", e.toString());         
                    }
                }                
            });
        } catch (Throwable e2) {
            if(e2 instanceof EsRejectedExecutionException) {
                log.debug("Unexpected exception while checking if searchguard index exists: {}", e2.toString());       
            } else {
                log.warn("Unexpected exception while checking if searchguard index exists: {}", e2.toString());         
            }
        }
        
        final Map<String, Settings> rs = new HashMap<String, Settings>(events.length);
        
        if(events == null || events.length == 0) {
            log.warn("No config events requested to load");
            return rs;
        }
        
        final BlockingQueue<Object> queue = new ArrayBlockingQueue<Object>(events.length);
        final MultiGetRequest mget = new MultiGetRequest();

        for (int i = 0; i < events.length; i++) {
            final String event = events[i];
            mget.add("searchguard", event, "0");
        }

        mget.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true"); //header needed here
        mget.refresh(true);
        mget.realtime(true);

        client.get().multiGet(mget, new ActionListener<MultiGetResponse>() {

            @Override
            public void onResponse(final MultiGetResponse mresponse) {

                final MultiGetItemResponse[] mres = mresponse.getResponses();

                for (int i = 0; i < mres.length; i++) {
                    final GetResponse response = mres[i].getResponse();
                    if (response == null) {
                        try {
                            queue.put("failure " + mres[i].getType() + " " + mres[i].getFailure().getMessage());
                        } catch (final InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    } else

                    if (response.isExists() && !response.isSourceEmpty()) {
                        try {
                            queue.put(response);
                        } catch (final InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    } else {
                        try {
                            queue.put(response.getType()+" does not exist or is empty");
                        } catch (final InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }
            }

            @Override
            public void onFailure(final Throwable e) {
                try {
                    queue.put(e);
                } catch (final InterruptedException e1) {
                    Thread.currentThread().interrupt();
                }
            }
        });

        Object response = null;
        try {
            response = queue.poll(2, TimeUnit.MINUTES);

            if (queue.size() == 0 && response != null && response instanceof Throwable) {
                throw ExceptionsHelper.convertToElastic((Throwable) response);
            }

            if (response instanceof GetResponse && response != null) {
                final GetResponse gs = (GetResponse) response;

                if (gs.isExists() && !gs.isSourceEmpty()) {
                    rs.put(gs.getType(), toSettings(gs.getSourceAsBytesRef()));
                }

            } else {
                log.debug("Cannot retrieve configuration (first object) due to {} (null means timeout)", response);
                
                if(response == null) {
                    log.warn("Cannot retrieve configuration (first object) due to timeout");
                }
            }

            for (int i = 0; i < events.length - 1; i++) {
                response = queue.poll(2, TimeUnit.MINUTES);
                if (response instanceof GetResponse && response != null) {
                    final GetResponse gs = (GetResponse) response;

                    if (gs.isExists() && !gs.isSourceEmpty()) {
                        rs.put(gs.getType(), toSettings(gs.getSourceAsBytesRef()));
                    }

                } else {
                    log.debug("Cannot retrieve configuration ("+(i+2)+" object) due to {} (null means timeout)", response);
                    
                    if(response == null) {
                        log.warn("Cannot retrieve configuration ("+(i+2)+" object) due to timeout");
                    }
                }
            }

        } catch (final InterruptedException e1) {
            Thread.currentThread().interrupt();
            //do not re-throw an exception here
            //just return what we have so far
        }

        return rs;
    }

    private static Settings toSettings(final BytesReference ref) {
        if (ref == null || ref.length() == 0) {
            throw new ElasticsearchException("ref invalid");
        }

        try {
            return Settings.builder().put(new JsonSettingsLoader().load(XContentHelper.createParser(ref))).build();
        } catch (final IOException e) {
            throw ExceptionsHelper.convertToElastic(e);
        }
    }

}
