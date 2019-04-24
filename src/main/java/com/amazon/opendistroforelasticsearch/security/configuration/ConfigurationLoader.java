/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.configuration;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.get.MultiGetItemResponse;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetResponse;
import org.elasticsearch.action.get.MultiGetResponse.Failure;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityDeprecationHandler;

class ConfigurationLoader {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Client client;
    //private final ThreadContext threadContext;
    private final String opendistrosecurityIndex;

    ConfigurationLoader(final Client client, ThreadPool threadPool, final Settings settings) {
        super();
        this.client = client;
        //this.threadContext = threadPool.getThreadContext();
        this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        log.debug("Index is: {}", opendistrosecurityIndex);
    }

    Map<String, Tuple<Long, Settings>> load(final String[] events, long timeout, TimeUnit timeUnit) throws InterruptedException, TimeoutException {
        final CountDownLatch latch = new CountDownLatch(events.length);
        final Map<String, Tuple<Long, Settings>> rs = new HashMap<String, Tuple<Long, Settings>>(events.length);

        loadAsync(events, new ConfigCallback() {

            @Override
            public void success(String id, Tuple<Long, Settings> settings) {
                if(latch.getCount() <= 0) {
                    log.error("Latch already counted down (for {} of {})  (index={})", id, Arrays.toString(events), opendistrosecurityIndex);
                }

                rs.put(id, settings);
                latch.countDown();
                if(log.isDebugEnabled()) {
                    log.debug("Received config for {} (of {}) with current latch value={}", id, Arrays.toString(events), latch.getCount());
                }
            }

            @Override
            public void singleFailure(Failure failure) {
                log.error("Failure {} retrieving configuration for {} (index={})", failure==null?null:failure.getMessage(), Arrays.toString(events), opendistrosecurityIndex);
            }

            @Override
            public void noData(String id) {
                log.warn("No data for {} while retrieving configuration for {}  (index={})", id, Arrays.toString(events), opendistrosecurityIndex);
            }

            @Override
            public void failure(Throwable t) {
                log.error("Exception {} while retrieving configuration for {}  (index={})",t,t.toString(), Arrays.toString(events), opendistrosecurityIndex);
            }
        });

        if(!latch.await(timeout, timeUnit)) {
            //timeout
            throw new TimeoutException("Timeout after "+timeout+""+timeUnit+" while retrieving configuration for "+Arrays.toString(events)+ "(index="+opendistrosecurityIndex+")");
        }

        return rs;
    }

    void loadAsync(final String[] events, final ConfigCallback callback) {
        if(events == null || events.length == 0) {
            log.warn("No config events requested to load");
            return;
        }

        final MultiGetRequest mget = new MultiGetRequest();

        for (int i = 0; i < events.length; i++) {
            final String event = events[i];
            mget.add(opendistrosecurityIndex, "security", event);
        }

        mget.refresh(true);
        mget.realtime(true);

        client.multiGet(mget, new ActionListener<MultiGetResponse>() {
            @Override
            public void onResponse(MultiGetResponse response) {
                MultiGetItemResponse[] responses = response.getResponses();
                for (int i = 0; i < responses.length; i++) {
                    MultiGetItemResponse singleResponse = responses[i];
                    if(singleResponse != null && !singleResponse.isFailed()) {
                        GetResponse singleGetResponse = singleResponse.getResponse();
                        if(singleGetResponse.isExists() && !singleGetResponse.isSourceEmpty()) {
                            //success
                            final Tuple<Long, Settings> _settings = toSettings(singleGetResponse);
                            if(_settings.v2() != null) {
                                callback.success(singleGetResponse.getId(), _settings);
                            } else {
                                log.error("Cannot parse settings for "+singleGetResponse.getId());
                            }
                        } else {
                            //does not exist or empty source
                            callback.noData(singleGetResponse.getId());
                        }
                    } else {
                        //failure
                        callback.singleFailure(singleResponse==null?null:singleResponse.getFailure());
                    }
                }
            }

            @Override
            public void onFailure(Exception e) {
                callback.failure(e);
            }
        });

    }

    private Tuple<Long, Settings> toSettings(GetResponse singleGetResponse) {
        final BytesReference ref = singleGetResponse.getSourceAsBytesRef();
        final String id = singleGetResponse.getId();
        final long version = singleGetResponse.getVersion();


        if (ref == null || ref.length() == 0) {
            log.error("Empty or null byte reference for {}", id);
            return null;
        }

        XContentParser parser = null;

        try {
            parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, OpenDistroSecurityDeprecationHandler.INSTANCE, ref, XContentType.JSON);
            parser.nextToken();
            parser.nextToken();

            if(!id.equals((parser.currentName()))) {
                log.error("Cannot parse config for type {} because {}!={}", id, id, parser.currentName());
                return null;
            }

            parser.nextToken();

            return new Tuple<Long, Settings>(version, Settings.builder().loadFromStream("dummy.json", new ByteArrayInputStream(parser.binaryValue()), true).build());
        } catch (final IOException e) {
            throw ExceptionsHelper.convertToElastic(e);
        } finally {
            if(parser != null) {
                try {
                    parser.close();
                } catch (IOException e) {
                    //ignore
                }
            }
        }
    }
}
