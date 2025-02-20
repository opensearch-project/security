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
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.search.ConstantScoreQuery;
import org.apache.lucene.search.Query;

import org.opensearch.OpenSearchException;
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
import org.opensearch.security.privileges.DocumentAllowList;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.dlsfls.DlsFlsBaseContext;
import org.opensearch.security.privileges.dlsfls.DlsFlsProcessedConfig;
import org.opensearch.security.privileges.dlsfls.DlsRestriction;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.privileges.dlsfls.FieldPrivileges;
import org.opensearch.security.support.ConfigConstants;

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
    private final Supplier<DlsFlsProcessedConfig> dlsFlsProcessedConfigSupplier;
    private final DlsFlsBaseContext dlsFlsBaseContext;

    public SecurityFlsDlsIndexSearcherWrapper(
        final IndexService indexService,
        final Settings settings,
        final AdminDNs adminDNs,
        final ClusterService clusterService,
        final AuditLog auditlog,
        final ComplianceIndexingOperationListener ciol,
        final PrivilegesEvaluator evaluator,
        final Supplier<DlsFlsProcessedConfig> dlsFlsProcessedConfigSupplier,
        final DlsFlsBaseContext dlsFlsBaseContext
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
        final boolean allowNowinDlsQueries = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, false);
        if (allowNowinDlsQueries) {
            nowInMillis = () -> System.currentTimeMillis();
        } else {
            nowInMillis = () -> { throw new IllegalArgumentException("'now' is not allowed in DLS queries"); };
        }
        log.debug("FLS/DLS {} enabled for index {}", this, indexService.index().getName());
        this.dlsFlsProcessedConfigSupplier = dlsFlsProcessedConfigSupplier;
        this.dlsFlsBaseContext = dlsFlsBaseContext;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected DirectoryReader dlsFlsWrap(final DirectoryReader reader, boolean isAdmin) throws IOException {

        final ShardId shardId = ShardUtils.extractShardId(reader);
        PrivilegesEvaluationContext privilegesEvaluationContext = this.dlsFlsBaseContext.getPrivilegesEvaluationContext();

        if (log.isTraceEnabled()) {
            log.trace("dlsFlsWrap(); index: {}; privilegeEvaluationContext: {}", index.getName(), privilegesEvaluationContext);
        }

        if (isAdmin || privilegesEvaluationContext == null) {
            return new DlsFlsFilterLeafReader.DlsFlsDirectoryReader(
                reader,
                FieldPrivileges.FlsRule.ALLOW_ALL,
                null,
                indexService,
                threadContext,
                clusterService,
                auditlog,
                FieldMasking.FieldMaskingRule.ALLOW_ALL,
                shardId,
                metaFields
            );
        }

        try {

            DlsFlsProcessedConfig config = this.dlsFlsProcessedConfigSupplier.get();
            DlsRestriction dlsRestriction;

            if (!this.dlsFlsBaseContext.isDlsDoneOnFilterLevel()) {
                dlsRestriction = config.getDocumentPrivileges().getRestriction(privilegesEvaluationContext, index.getName());
            } else {
                dlsRestriction = DlsRestriction.NONE;
            }

            FieldPrivileges.FlsRule flsRule = config.getFieldPrivileges().getRestriction(privilegesEvaluationContext, index.getName());
            FieldMasking.FieldMaskingRule fmRule = config.getFieldMasking().getRestriction(privilegesEvaluationContext, index.getName());

            Query dlsQuery;

            if (dlsRestriction.isUnrestricted()) {
                dlsQuery = null;
            } else {
                QueryShardContext queryShardContext = this.indexService.newQueryShardContext(shardId.getId(), null, nowInMillis, null);
                dlsQuery = new ConstantScoreQuery(dlsRestriction.toBooleanQueryBuilder(queryShardContext, null).build());
            }

            DocumentAllowList documentAllowList = DocumentAllowList.get(threadContext);

            if (documentAllowList.isEntryForIndexPresent(index.getName())) {
                // The documentAllowList is needed for two cases:
                // - DLS rules which use "term lookup queries" and thus need to access indices for which no privileges are present
                // - Dashboards multi tenancy which can redirect index accesses to indices for which no normal index privileges are present

                if (!dlsRestriction.isUnrestricted() && documentAllowList.isAllowed(index.getName(), "*")) {
                    dlsRestriction = DlsRestriction.NONE;
                    log.debug("Lifting DLS for {} due to present document allowlist", index.getName());
                    dlsQuery = null;

                }

                if (!flsRule.isAllowAll() || !fmRule.isAllowAll()) {
                    log.debug("Lifting FLS/FM for {} due to present document allowlist", index.getName());
                    flsRule = FieldPrivileges.FlsRule.ALLOW_ALL;
                    fmRule = FieldMasking.FieldMaskingRule.ALLOW_ALL;
                }
            }

            if (log.isTraceEnabled()) {
                log.trace(
                    "dlsFlsWrap(); index: {}; dlsRestriction: {}; flsRule: {}; fmRule: {}",
                    index.getName(),
                    dlsRestriction,
                    flsRule,
                    fmRule
                );
            }

            return new DlsFlsFilterLeafReader.DlsFlsDirectoryReader(
                reader,
                flsRule,
                dlsQuery,
                indexService,
                threadContext,
                clusterService,
                auditlog,
                fmRule,
                shardId,
                metaFields
            );

        } catch (PrivilegesEvaluationException e) {
            log.error("Error while evaluating DLS/FLS for {}", this.index.getName(), e);
            throw new OpenSearchException("Error while evaluating DLS/FLS", e);
        }
    }
}
