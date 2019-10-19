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

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.amazon.opendistroforelasticsearch.security.support.ConfigHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.get.MultiGetItemResponse;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetResponse;
import org.elasticsearch.action.get.MultiGetResponse.Failure;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityDeprecationHandler;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityUtils;

public class ConfigurationLoaderSecurity7 {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Client client;
    private final String securityIndex;
    private final ClusterService cs;
    private final Settings settings;

    ConfigurationLoaderSecurity7(final Client client, ThreadPool threadPool, final Settings settings, ClusterService cs) {
        super();
        this.client = client;
        this.settings = settings;
        this.securityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.cs = cs;
        log.debug("Index is: {}", securityIndex);
    }

    Map<CType, SecurityDynamicConfiguration<?>> load(final CType[] events, long timeout, TimeUnit timeUnit, boolean acceptInvalid) throws InterruptedException, TimeoutException {
        final CountDownLatch latch = new CountDownLatch(events.length);
        final Map<CType, SecurityDynamicConfiguration<?>> rs = new HashMap<>(events.length);

        loadAsync(events, new ConfigCallback() {

            @Override
            public void success(SecurityDynamicConfiguration<?> dConf) {
                if(latch.getCount() <= 0) {
                    log.error("Latch already counted down (for {} of {})  (index={})", dConf.getCType().toLCString(), Arrays.toString(events), securityIndex);
                }

                rs.put(dConf.getCType(), dConf);
                latch.countDown();
                if(log.isDebugEnabled()) {
                    log.debug("Received config for {} (of {}) with current latch value={}", dConf.getCType().toLCString(), Arrays.toString(events), latch.getCount());
                }
            }

            @Override
            public void singleFailure(Failure failure) {
                log.error("Failure {} retrieving configuration for {} (index={})", failure==null?null:failure.getMessage(), Arrays.toString(events), securityIndex);
            }

            @Override
            public void noData(String id, String type) {
                CType cType = CType.fromString(id);

                //when index was created with ES 6 there are no separate tenants. So we load just empty ones.
                //when index was created with ES 7 and type not "security" (ES 6 type) there are no rolemappings anymore.
                if(cs.state().metaData().index(securityIndex).getCreationVersion().before(Version.V_7_0_0) || "security".equals(type)) {
                    //created with SG 6
                    //skip tenants

                    if(log.isDebugEnabled()) {
                        log.debug("Skip tenants because we not yet migrated to ES 7 (index was created with ES 6 and type is legacy [{}])", type);
                    }

                    if(cType == CType.TENANTS) {
                        rs.put(cType, SecurityDynamicConfiguration.empty());
                        latch.countDown();
                        return;
                    }
                }

                // Since NODESDN is newly introduced data-type applying for existing clusters as well, we make it backward compatible by returning valid empty
                // SecurityDynamicConfiguration.
                if(cType == CType.NODESDN) {
                    try {
                        SecurityDynamicConfiguration<?> empty = ConfigHelper.createEmptySdc(cType, ConfigurationRepository.getDefaultConfigVersion());
                        rs.put(cType, empty);
                        latch.countDown();
                        return;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }

                log.warn("No data for {} while retrieving configuration for {}  (index={} and type={})", id, Arrays.toString(events), securityIndex, type);
            }

            @Override
            public void failure(Throwable t) {
                log.error("Exception {} while retrieving configuration for {}  (index={})",t,t.toString(), Arrays.toString(events), securityIndex);
            }
        }, acceptInvalid);

        if(!latch.await(timeout, timeUnit)) {
            //timeout
            throw new TimeoutException("Timeout after "+timeout+""+timeUnit+" while retrieving configuration for "+Arrays.toString(events)+ "(index="+securityIndex+")");
        }

        return rs;
    }

    void loadAsync(final CType[] events, final ConfigCallback callback, boolean acceptInvalid) {
        if(events == null || events.length == 0) {
            log.warn("No config events requested to load");
            return;
        }

        final MultiGetRequest mget = new MultiGetRequest();

        for (int i = 0; i < events.length; i++) {
            final String event = events[i].toLCString();
            mget.add(securityIndex, event);
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
                            try {
                                final SecurityDynamicConfiguration<?> dConf = toConfig(singleGetResponse, acceptInvalid);
                                if(dConf != null) {
                                    callback.success(dConf.deepClone());
                                } else {
                                    callback.failure(new Exception("Cannot parse settings for "+singleGetResponse.getId()));
                                }
                            } catch (Exception e) {
                                log.error(e.toString(),e);
                                callback.failure(e);
                            }
                        } else {
                            //does not exist or empty source
                            callback.noData(singleGetResponse.getId(), singleGetResponse.getType());
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

    private SecurityDynamicConfiguration<?> toConfig(GetResponse singleGetResponse, boolean acceptInvalid) throws Exception {
        final BytesReference ref = singleGetResponse.getSourceAsBytesRef();
        final String id = singleGetResponse.getId();
        final long seqNo = singleGetResponse.getSeqNo();
        final long primaryTerm = singleGetResponse.getPrimaryTerm();



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

            final String jsonAsString = OpenDistroSecurityUtils.replaceEnvVars(new String(parser.binaryValue()), settings);
            final JsonNode jsonNode = DefaultObjectMapper.readTree(jsonAsString);
            int configVersion = 1;



            if(jsonNode.get("_meta") != null) {
                assert jsonNode.get("_meta").get("type").asText().equals(id);
                configVersion = jsonNode.get("_meta").get("config_version").asInt();
            }

            if(log.isDebugEnabled()) {
                log.debug("Load "+id+" with version "+configVersion);
            }

            if (CType.ACTIONGROUPS.toLCString().equals(id)) {
                try {
                    return SecurityDynamicConfiguration.fromJson(jsonAsString, CType.fromString(id), configVersion, seqNo, primaryTerm, acceptInvalid);
                } catch (Exception e) {
                    if(log.isDebugEnabled()) {
                        log.debug("Unable to load "+id+" with version "+configVersion+" - Try loading legacy format ...");
                    }
                    return SecurityDynamicConfiguration.fromJson(jsonAsString, CType.fromString(id), 0, seqNo, primaryTerm, acceptInvalid);
                }
            }
            return SecurityDynamicConfiguration.fromJson(jsonAsString, CType.fromString(id), configVersion, seqNo, primaryTerm, acceptInvalid);

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
