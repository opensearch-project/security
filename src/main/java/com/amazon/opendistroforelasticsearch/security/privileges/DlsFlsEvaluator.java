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

package com.amazon.opendistroforelasticsearch.security.privileges;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModel.SecurityRoles;
import com.amazon.opendistroforelasticsearch.security.support.Base64Helper;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.amazon.opendistroforelasticsearch.security.user.User;

public class DlsFlsEvaluator {

    protected final Logger log = LogManager.getLogger(this.getClass());

    private final ThreadPool threadPool;

    public DlsFlsEvaluator(Settings settings, ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    public PrivilegesEvaluatorResponse evaluate(final ClusterService clusterService, final IndexNameExpressionResolver resolver, final Resolved requestedResolved, final User user,
            final SecurityRoles securityRoles, final PrivilegesEvaluatorResponse presponse) {

        ThreadContext threadContext = threadPool.getThreadContext();

        // maskedFields
        final Map<String, Set<String>> maskedFieldsMap = securityRoles.getMaskedFields(user, resolver, clusterService);

        if (maskedFieldsMap != null && !maskedFieldsMap.isEmpty()) {
            if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER) != null) {
                if (!maskedFieldsMap.equals(Base64Helper.deserializeObject(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER)))) {
                    throw new ElasticsearchSecurityException(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER + " does not match (Security 901D)");
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER + " already set");
                    }
                }
            } else {
                threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, Base64Helper.serializeObject((Serializable) maskedFieldsMap));
                if (log.isDebugEnabled()) {
                    log.debug("attach masked fields info: {}", maskedFieldsMap);
                }
            }
        
            presponse.maskedFields = new HashMap<>(maskedFieldsMap);
            
            if (!requestedResolved.getAllIndices().isEmpty()) {
                for (Iterator<Entry<String, Set<String>>> it = presponse.maskedFields.entrySet().iterator(); it.hasNext();) {
                    Entry<String, Set<String>> entry = it.next();
                    if (!WildcardMatcher.matchAny(entry.getKey(), requestedResolved.getAllIndices(), false)) {
                        it.remove();
                    }
                }
            }     
        }

        

        // attach dls/fls map if not already done
        // TODO do this only if advanced module are loaded
        final Tuple<Map<String, Set<String>>, Map<String, Set<String>>> dlsFls = securityRoles.getDlsFls(user, resolver, clusterService);
        final Map<String, Set<String>> dlsQueries = dlsFls.v1();
        final Map<String, Set<String>> flsFields = dlsFls.v2();

        if (!dlsQueries.isEmpty()) {

            if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER) != null) {
                if (!dlsQueries.equals(Base64Helper.deserializeObject(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER)))) {
                    throw new ElasticsearchSecurityException(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER + " does not match (Security 900D)");
                }
            } else {
                threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, Base64Helper.serializeObject((Serializable) dlsQueries));
                if (log.isDebugEnabled()) {
                    log.debug("attach DLS info: {}", dlsQueries);
                }
            }

            presponse.queries = new HashMap<>(dlsQueries);

            if (!requestedResolved.getAllIndices().isEmpty()) {
                for (Iterator<Entry<String, Set<String>>> it = presponse.queries.entrySet().iterator(); it.hasNext();) {
                    Entry<String, Set<String>> entry = it.next();
                    if (!WildcardMatcher.matchAny(entry.getKey(), requestedResolved.getAllIndices(), false)) {
                        it.remove();
                    }
                }
            }

        }

        if (!flsFields.isEmpty()) {

            if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER) != null) {
                if (!flsFields.equals(Base64Helper.deserializeObject(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER)))) {
                    throw new ElasticsearchSecurityException(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER + " does not match (Security 901D)");
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER + " already set");
                    }
                }
            } else {
                threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, Base64Helper.serializeObject((Serializable) flsFields));
                if (log.isDebugEnabled()) {
                    log.debug("attach FLS info: {}", flsFields);
                }
            }

            presponse.allowedFlsFields = new HashMap<>(flsFields);

            if (!requestedResolved.getAllIndices().isEmpty()) {
                for (Iterator<Entry<String, Set<String>>> it = presponse.allowedFlsFields.entrySet().iterator(); it.hasNext();) {
                    Entry<String, Set<String>> entry = it.next();
                    if (!WildcardMatcher.matchAny(entry.getKey(), requestedResolved.getAllIndices(), false)) {
                        it.remove();
                    }
                }
            }
        }

        if (requestedResolved == Resolved._EMPTY) {
            presponse.allowed = true;
            return presponse.markComplete();
        }
        
        return presponse;
    }
}
