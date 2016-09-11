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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.get.MultiGetItemResponse;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetResponse;
import org.elasticsearch.action.get.MultiGetResponse.Failure;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.loader.JsonSettingsLoader;
import org.elasticsearch.common.xcontent.XContentHelper;

import com.floragunn.searchguard.support.ConfigConstants;

public class ConfigurationLoader {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Provider<Client> client;

    private final String searchguardIndex;
    
    @Inject
    public ConfigurationLoader(final Provider<Client> client, final Settings settings) {
        super();
        this.client = client;
        this.searchguardIndex = settings.get(ConfigConstants.SG_CONFIG_INDEX, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        log.debug("Index is: {}", searchguardIndex);
    }
    
    public Map<String, Settings> load(final String[] events, long timeout, TimeUnit timeUnit) throws InterruptedException, TimeoutException {
        final CountDownLatch latch = new CountDownLatch(events.length);
        final Map<String, Settings> rs = new HashMap<String, Settings>(events.length);
        
        loadAsync(events, new ConfigCallback() {
            
            @Override
            public void success(String type, Settings settings) {
                if(latch.getCount() <= 0) {
                    log.error("Latch already counted down (for {} of {})  (index={})", type, Arrays.toString(events), searchguardIndex);
                }
                
                rs.put(type, settings);
                latch.countDown();
                if(log.isDebugEnabled()) {
                    log.debug("Received config for {} (of {}) with current latch value={}", type, Arrays.toString(events), latch.getCount());
                }
            }
            
            @Override
            public void singleFailure(Failure failure) {
                log.error("Failure {} retrieving configuration for {} (index={})", failure==null?null:failure.getMessage(), Arrays.toString(events), searchguardIndex);
            }
            
            @Override
            public void noData(String type) {
                log.error("No data for {} while retrieving configuration for {}  (index={})", type, Arrays.toString(events), searchguardIndex);
            }
            
            @Override
            public void failure(Throwable t) {
                log.error("Exception {} while retrieving configuration for {}  (index={})",t,t.toString(), Arrays.toString(events), searchguardIndex);
            }
        });
        
        if(!latch.await(timeout, timeUnit)) {
            //timeout
            throw new TimeoutException("Timeout after "+timeout+""+timeUnit+" while retrieving configuration for "+Arrays.toString(events)+ "(index="+searchguardIndex+")");
        }
        
        return rs;
    }
    
    public void loadAsync(final String[] events, final ConfigCallback callback) {        
        if(events == null || events.length == 0) {
            log.warn("No config events requested to load");
            return;
        }
        
        final MultiGetRequest mget = new MultiGetRequest();

        for (int i = 0; i < events.length; i++) {
            final String event = events[i];
            mget.add(searchguardIndex, event, "0");
        }

        mget.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true"); //header needed here
        mget.refresh(true);
        mget.realtime(true);
        
        client.get().multiGet(mget, new ActionListener<MultiGetResponse>() {

            @Override
            public void onResponse(MultiGetResponse response) {
                MultiGetItemResponse[] responses = response.getResponses();
                for (int i = 0; i < responses.length; i++) {
                    MultiGetItemResponse singleResponse = responses[i];
                    if(singleResponse != null && !singleResponse.isFailed()) {
                        GetResponse singleGetResponse = singleResponse.getResponse();
                        if(singleGetResponse.isExists() && !singleGetResponse.isSourceEmpty()) {
                            //success
                            final Settings _settings = toSettings(singleGetResponse.getSourceAsBytesRef(), singleGetResponse.getType());
                            if(_settings != null) {
                                callback.success(singleGetResponse.getType(), _settings);
                            }
                        } else {
                            //does not exist or empty source
                            callback.noData(singleGetResponse.getType());
                        }
                    } else {
                        //failure
                        callback.singleFailure(singleResponse==null?null:singleResponse.getFailure());
                    }
                }
            }

            @Override
            public void onFailure(Throwable e) {
                callback.failure(e);
            }
            
        });
    }

    private Settings toSettings(final BytesReference ref, String type) {
        if (ref == null || ref.length() == 0) {
            log.error("Null or empty BytesReference for "+type);
            return null;
        }

        try {
            return Settings.builder().put(new JsonSettingsLoader().load(XContentHelper.createParser(ref))).build();
        } catch (final Exception e) {
            log.error("Unable to parse {} due to {}",e, type, e.toString());
            return null;
        }
    }

}
