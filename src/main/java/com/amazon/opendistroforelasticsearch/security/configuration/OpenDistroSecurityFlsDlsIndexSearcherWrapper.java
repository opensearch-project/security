/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.configuration;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.search.Query;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.mapper.MapperService;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.index.shard.ShardUtils;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceIndexingOperationListener;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.HeaderHelper;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityUtils;

import com.google.common.collect.Sets;

public class OpenDistroSecurityFlsDlsIndexSearcherWrapper extends OpenDistroSecurityIndexSearcherWrapper {

    private static final Set<String> metaFields = Sets.union(Sets.newHashSet("_source", "_version", "_field_names", "_seq_no", "_primary_term"),
            Sets.newHashSet(MapperService.getAllMetaFields()));
    private final ClusterService clusterService;
    private final IndexService indexService;
    private final ComplianceConfig complianceConfig;
    private final AuditLog auditlog;
    private final LongSupplier nowInMillis;

    public OpenDistroSecurityFlsDlsIndexSearcherWrapper(final IndexService indexService, final Settings settings,
            final AdminDNs adminDNs, final ClusterService clusterService, final AuditLog auditlog,
            final ComplianceIndexingOperationListener ciol, final ComplianceConfig complianceConfig, final PrivilegesEvaluator evaluator) {
        super(indexService, settings, adminDNs, evaluator);
        ciol.setIs(indexService);
        this.clusterService = clusterService;
        this.indexService = indexService;
        this.complianceConfig = complianceConfig;
        this.auditlog = auditlog;
        final boolean allowNowinDlsQueries = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, false);
        if (allowNowinDlsQueries) {
            nowInMillis = () -> System.currentTimeMillis();
        } else {
            nowInMillis = () -> {throw new IllegalArgumentException("'now' is not allowed in DLS queries");};
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    protected DirectoryReader dlsFlsWrap(final DirectoryReader reader, boolean isAdmin) throws IOException {

        final ShardId shardId = ShardUtils.extractShardId(reader);

        Set<String> flsFields = null;
        Set<String> maskedFields = null;
        Query dlsQuery = null;

        if(!isAdmin) {

            final Map<String, Set<String>> allowedFlsFields = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadContext,
                    ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER);
            final Map<String, Set<String>> queries = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadContext,
                    ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER);
            final Map<String, Set<String>> maskedFieldsMap = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadContext,
                    ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER);

            final String flsEval = OpenDistroSecurityUtils.evalMap(allowedFlsFields, index.getName());
            final String dlsEval = OpenDistroSecurityUtils.evalMap(queries, index.getName());
            final String maskedEval = OpenDistroSecurityUtils.evalMap(maskedFieldsMap, index.getName());

            if (flsEval != null) {
                flsFields = new HashSet<>(metaFields);
                flsFields.addAll(allowedFlsFields.get(flsEval));
            }



            if (dlsEval != null) {
                final Set<String> unparsedDlsQueries = queries.get(dlsEval);
                if(unparsedDlsQueries != null && !unparsedDlsQueries.isEmpty()) {
                    //disable reader optimizations
                    dlsQuery = DlsQueryParser.parse(unparsedDlsQueries, this.indexService.newQueryShardContext(shardId.getId(), null, nowInMillis, null)
                            , this.indexService.xContentRegistry());
                }
            }

            if (maskedEval != null) {
                maskedFields = new HashSet<>();
                maskedFields.addAll(maskedFieldsMap.get(maskedEval));
            }
        }

        return new DlsFlsFilterLeafReader.DlsFlsDirectoryReader(reader, flsFields, dlsQuery,
                indexService, threadContext, clusterService, complianceConfig, auditlog, maskedFields, shardId);
    }
}
