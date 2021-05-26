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

package org.opensearch.security.configuration;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.support.SecurityUtils;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.search.Query;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.IndexService;
import org.opensearch.index.mapper.IgnoredFieldMapper;
import org.opensearch.index.shard.ShardId;
import org.opensearch.index.shard.ShardUtils;

import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.compliance.ComplianceIndexingOperationListener;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;

import com.google.common.collect.Sets;

public class SecurityFlsDlsIndexSearcherWrapper extends SecurityIndexSearcherWrapper {

    // TODO: the list is outdated. It is necessary to change how meta fields are handled in the near future.
    //  We may consider using MapperService.isMetadataField() instead of relying on the static set or
    //  (if it is too costly or does not meet requirements) use IndicesModule.getBuiltInMetadataFields()
    //  for OpenSearch version specific Set of meta fields
    private static final Set<String> metaFields = Sets.newHashSet("_source", "_version", "_field_names",
            "_seq_no", "_primary_term", "_id", IgnoredFieldMapper.NAME, "_index", "_routing", "_size", "_timestamp", "_ttl", "_type");
    private final ClusterService clusterService;
    private final IndexService indexService;
    private final AuditLog auditlog;
    private final LongSupplier nowInMillis;
    private final Salt salt;

    public SecurityFlsDlsIndexSearcherWrapper(final IndexService indexService, final Settings settings,
                                              final AdminDNs adminDNs, final ClusterService clusterService, final AuditLog auditlog,
                                              final ComplianceIndexingOperationListener ciol, final PrivilegesEvaluator evaluator, final Salt salt) {
        super(indexService, settings, adminDNs, evaluator);
        ciol.setIs(indexService);
        this.clusterService = clusterService;
        this.indexService = indexService;
        this.auditlog = auditlog;
        final boolean allowNowinDlsQueries = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, false);
        if (allowNowinDlsQueries) {
            nowInMillis = () -> System.currentTimeMillis();
        } else {
            nowInMillis = () -> {throw new IllegalArgumentException("'now' is not allowed in DLS queries");};
        }
        log.debug("FLS/DLS {} enabled for index {}", this, indexService.index().getName());
        this.salt = salt;
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

            final String flsEval = SecurityUtils.evalMap(allowedFlsFields, index.getName());
            final String dlsEval = SecurityUtils.evalMap(queries, index.getName());
            final String maskedEval = SecurityUtils.evalMap(maskedFieldsMap, index.getName());

            if (flsEval != null) {
                flsFields = Sets.union(metaFields, allowedFlsFields.get(flsEval));
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
                indexService, threadContext, clusterService, auditlog, maskedFields, shardId, salt);
    }
}
