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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

import com.google.common.collect.Sets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.search.ConstantScoreQuery;
import org.apache.lucene.search.Query;

import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.IndexService;
import org.opensearch.index.mapper.SeqNoFieldMapper;
import org.opensearch.index.query.QueryShardContext;
import org.opensearch.index.shard.ShardUtils;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.compliance.ComplianceIndexingOperationListener;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.support.SecurityUtils;

public class SecurityFlsDlsIndexSearcherWrapper extends SystemIndexSearcherWrapper {

    public final Logger log = LogManager.getLogger(this.getClass());

    private final Set<String> metaFields;
    public static final Set<String> META_FIELDS_BEFORE_7DOT8 = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList("_timestamp", "_ttl", "_type"))
    );
    private final ClusterService clusterService;
    private final IndexService indexService;
    private final AuditLog auditlog;
    private final LongSupplier nowInMillis;
    private final DlsQueryParser dlsQueryParser;
    private final Salt salt;

    public SecurityFlsDlsIndexSearcherWrapper(
        final IndexService indexService,
        final Settings settings,
        final AdminDNs adminDNs,
        final ClusterService clusterService,
        final AuditLog auditlog,
        final ComplianceIndexingOperationListener ciol,
        final PrivilegesEvaluator evaluator,
        final Salt salt
    ) {
        super(indexService, settings, adminDNs, evaluator);
        Set<String> metadataFieldsCopy;
        if (indexService.getMetadata().getState() == IndexMetadata.State.CLOSE) {
            if (log.isDebugEnabled()) {
                log.debug(
                    "{} was closed. Setting metadataFields to empty. Closed index is not searchable.",
                    indexService.index().getName()
                );
            }
            metadataFieldsCopy = Collections.emptySet();
        } else {
            metadataFieldsCopy = new HashSet<>(indexService.mapperService().getMetadataFields());
            SeqNoFieldMapper.SequenceIDFields sequenceIDFields = SeqNoFieldMapper.SequenceIDFields.emptySeqID();
            metadataFieldsCopy.add(sequenceIDFields.primaryTerm.name());
            metadataFieldsCopy.addAll(META_FIELDS_BEFORE_7DOT8);
        }
        metaFields = metadataFieldsCopy;
        ciol.setIs(indexService);
        this.clusterService = clusterService;
        this.indexService = indexService;
        this.auditlog = auditlog;
        this.dlsQueryParser = new DlsQueryParser(indexService.xContentRegistry());
        final boolean allowNowinDlsQueries = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, false);
        if (allowNowinDlsQueries) {
            nowInMillis = () -> System.currentTimeMillis();
        } else {
            nowInMillis = () -> { throw new IllegalArgumentException("'now' is not allowed in DLS queries"); };
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

        if (!isAdmin) {

            final Map<String, Set<String>> allowedFlsFields = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(
                threadContext,
                ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER
            );
            final Map<String, Set<String>> queries = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(
                threadContext,
                ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER
            );
            final Map<String, Set<String>> maskedFieldsMap = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(
                threadContext,
                ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER
            );

            final String flsEval = SecurityUtils.evalMap(allowedFlsFields, index.getName());
            final String dlsEval = SecurityUtils.evalMap(queries, index.getName());
            final String maskedEval = SecurityUtils.evalMap(maskedFieldsMap, index.getName());

            if (flsEval != null) {
                flsFields = Sets.union(metaFields, allowedFlsFields.get(flsEval));
            }

            if (dlsEval != null) {
                Set<String> unparsedDlsQueries = queries.get(dlsEval);

                if (unparsedDlsQueries != null && !unparsedDlsQueries.isEmpty()) {
                    QueryShardContext queryShardContext = this.indexService.newQueryShardContext(shardId.getId(), null, nowInMillis, null);
                    // no need for scoring here, so its possible to wrap this in a
                    // ConstantScoreQuery
                    dlsQuery = new ConstantScoreQuery(dlsQueryParser.parse(unparsedDlsQueries, queryShardContext).build());
                }
            }

            if (maskedEval != null) {
                maskedFields = new HashSet<>();
                maskedFields.addAll(maskedFieldsMap.get(maskedEval));
            }
        }

        return new DlsFlsFilterLeafReader.DlsFlsDirectoryReader(
            reader,
            flsFields,
            dlsQuery,
            indexService,
            threadContext,
            clusterService,
            auditlog,
            maskedFields,
            shardId,
            salt
        );
    }
}
