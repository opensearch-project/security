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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.configuration;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionListener;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.get.MultiGetResponse.Failure;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.ConfigHelper;
import org.opensearch.security.support.SecurityUtils;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.core.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;

public class ConfigurationLoaderSecurity7 {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Client client;
    private final String securityIndex;
    private final ClusterService cs;
    private final Settings settings;
    private final AtomicBoolean isAuditConfigDocPresentInIndex = new AtomicBoolean();

    ConfigurationLoaderSecurity7(final Client client, ThreadPool threadPool, final Settings settings, ClusterService cs) {
        super();
        this.client = client;
        this.settings = settings;
        this.securityIndex = settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.cs = cs;
        log.debug("Index is: {}", securityIndex);
    }

    /**
     * Checks if audit config doc is present in security index
     * @return true/false
     */
    boolean isAuditConfigDocPresentInIndex() {
        return isAuditConfigDocPresentInIndex.get();
    }

    Map<CType, SecurityDynamicConfiguration<?>> load(final CType[] events, long timeout, TimeUnit timeUnit, boolean acceptInvalid) throws InterruptedException, TimeoutException {
        final CountDownLatch latch = new CountDownLatch(events.length);
        final Map<CType, SecurityDynamicConfiguration<?>> rs = new HashMap<>(events.length);
        final boolean isDebugEnabled = log.isDebugEnabled();
        loadAsync(events, new ConfigCallback() {

            @Override
            public void success(SecurityDynamicConfiguration<?> dConf) {
                if(latch.getCount() <= 0) {
                    log.error("Latch already counted down (for {} of {})  (index={})", dConf.getCType().toLCString(), Arrays.toString(events), securityIndex);
                }

                // Audit configuration doc is available in the index.
                // Configuration can be hot-reloaded.
                if (dConf.getCType() == CType.AUDIT) {
                    isAuditConfigDocPresentInIndex.set(true);
                }

                rs.put(dConf.getCType(), dConf);
                latch.countDown();
                if (isDebugEnabled) {
                    log.debug("Received config for {} (of {}) with current latch value={}", dConf.getCType().toLCString(), Arrays.toString(events), latch.getCount());
                }
            }

            @Override
            public void singleFailure(Failure failure) {
                log.error("Failure {} retrieving configuration for {} (index={})", failure==null?null:failure.getMessage(), Arrays.toString(events), securityIndex);
            }

            @Override
            public void noData(String id) {
                CType cType = CType.fromString(id);

                // Since NODESDN is newly introduced data-type applying for existing clusters as well, we make it backward compatible by returning valid empty
                // SecurityDynamicConfiguration.
                // Same idea for new setting WHITELIST/ALLOWLIST
                if (cType == CType.NODESDN || cType == CType.WHITELIST || cType == CType.ALLOWLIST) {
                    try {
                        SecurityDynamicConfiguration<?> empty = ConfigHelper.createEmptySdc(cType, ConfigurationRepository.getDefaultConfigVersion());
                        rs.put(cType, empty);
                        latch.countDown();
                        return;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }

                if(cType == CType.AUDIT) {
                    // Audit configuration doc is not available in the index.
                    // Configuration cannot be hot-reloaded.
                    isAuditConfigDocPresentInIndex.set(false);
                    try {
                        SecurityDynamicConfiguration<?> empty = ConfigHelper.createEmptySdc(cType, ConfigurationRepository.getDefaultConfigVersion());
                        empty.putCObject("config", AuditConfig.from(settings));
                        rs.put(cType, empty);
                        latch.countDown();
                        return;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }

                log.warn("No data for {} while retrieving configuration for {}  (index={})", id, Arrays.toString(events), securityIndex);
            }

            @Override
            public void failure(Throwable t) {
                log.error("Exception while retrieving configuration for {} (index={})", Arrays.toString(events), securityIndex, t);
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
                                log.error(e.toString());
                                callback.failure(e);
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
            parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, ref, XContentType.JSON);
            parser.nextToken();
            parser.nextToken();

            if(!id.equals((parser.currentName()))) {
                log.error("Cannot parse config for type {} because {}!={}", id, id, parser.currentName());
                return null;
            }

            parser.nextToken();

            final String jsonAsString = SecurityUtils.replaceEnvVars(new String(parser.binaryValue(), StandardCharsets.UTF_8), settings);
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
