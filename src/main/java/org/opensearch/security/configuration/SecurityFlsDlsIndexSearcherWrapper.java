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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
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
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.IndexService;
import org.opensearch.index.mapper.SeqNoFieldMapper;
import org.opensearch.index.query.QueryShardContext;
import org.opensearch.index.shard.ShardUtils;
import org.opensearch.security.OpenSearchSecurityPlugin;
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
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.spi.resources.ResourceSharingException;
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
    private final ResourceAccessHandler resourceAccessHandler;
    private final boolean isResourceSharingEnabled;

    public SecurityFlsDlsIndexSearcherWrapper(
        final IndexService indexService,
        final Settings settings,
        final AdminDNs adminDNs,
        final ClusterService clusterService,
        final AuditLog auditlog,
        final ComplianceIndexingOperationListener ciol,
        final PrivilegesEvaluator evaluator,
        final Supplier<DlsFlsProcessedConfig> dlsFlsProcessedConfigSupplier,
        final DlsFlsBaseContext dlsFlsBaseContext,
        final ResourceAccessHandler resourceAccessHandler
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
        this.resourceAccessHandler = resourceAccessHandler;
        this.isResourceSharingEnabled = settings.getAsBoolean(
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED,
            ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT
        );
    }

    @SuppressWarnings("unchecked")
    @Override
    protected DirectoryReader dlsFlsWrap(final DirectoryReader reader, boolean isAdmin) throws IOException {
        final ShardId shardId = ShardUtils.extractShardId(reader);
        PrivilegesEvaluationContext privilegesEvaluationContext = this.dlsFlsBaseContext.getPrivilegesEvaluationContext();
        final String indexName = (shardId != null) ? shardId.getIndexName() : null;

        if (log.isTraceEnabled()) {
            log.trace("dlsFlsWrap(); index: {}; isAdmin: {}", indexName, isAdmin);
        }

        // 1. If user is admin, or we have no shard/index info, just wrap with default logic (no doc-level restriction).
        if (isAdmin || privilegesEvaluationContext == null) {
            return wrapWithDefaultDlsFls(reader, shardId);
        }

        assert !Strings.isNullOrEmpty(indexName);
        // 2. If resource sharing is disabled or this is not a resource index, fallback to standard DLS/FLS logic.
        if (!this.isResourceSharingEnabled || !OpenSearchSecurityPlugin.getResourceIndices().contains(indexName)) {
            return wrapStandardDlsFls(privilegesEvaluationContext, reader, shardId, indexName, isAdmin);
        }

        // TODO see if steps 3,4,5 can be changed to be completely asynchronous
        // 3.Since we need DirectoryReader *now*, we'll block the thread using a CountDownLatch until the async call completes.
        final AtomicReference<Set<String>> resourceIdsRef = new AtomicReference<>(Collections.emptySet());
        final AtomicReference<Exception> exceptionRef = new AtomicReference<>(null);
        final CountDownLatch latch = new CountDownLatch(1);

        // 4. Perform the async call to fetch resource IDs
        this.resourceAccessHandler.getAccessibleResourceIdsForCurrentUser(indexName, ActionListener.wrap(resourceIds -> {
            log.debug("Fetched resource IDs for index '{}': {}", indexName, resourceIds);
            resourceIdsRef.set(resourceIds);
            latch.countDown();
        }, ex -> {
            log.error("Failed to fetch resource IDs for index '{}': {}", indexName, ex.getMessage(), ex);
            exceptionRef.set(ex);
            latch.countDown();
        }));

        // 5. Block until the async call completes
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for resource IDs", e);
        }

        // 6. Throw any errors
        if (exceptionRef.get() != null) {
            throw new ResourceSharingException("Failed to get resource IDs for index: " + indexName, exceptionRef.get());
        }

        // 7. If the user has no accessible resources, produce a reader that yields zero documents
        final Set<String> resourceIds = resourceIdsRef.get();
        if (resourceIds.isEmpty()) {
            log.debug("User has no accessible resources in index '{}'; returning EmptyDirectoryReader.", indexName);
            return new EmptyFilterLeafReader.EmptyDirectoryReader(reader);
        }

        // 8. Build the resource-based query to restrict docs
        final QueryShardContext queryShardContext = this.indexService.newQueryShardContext(shardId.getId(), null, nowInMillis, null);
        final Query resourceQuery = this.resourceAccessHandler.createResourceDLSQuery(resourceIds, queryShardContext);

        log.debug("Applying resource-based DLS query for index '{}'", indexName);

        // 9. Wrap with a DLS/FLS DirectoryReader that includes doc-level restriction (resourceQuery),
        // with FLS (ALLOW_ALL) since we don't need field-level restrictions here.
        return new DlsFlsFilterLeafReader.DlsFlsDirectoryReader(
            reader,
            FieldPrivileges.FlsRule.ALLOW_ALL,
            resourceQuery,
            indexService,
            threadContext,
            clusterService,
            auditlog,
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            shardId,
            metaFields
        );
    }

    /**
     * Wrap the reader with an "ALLOW_ALL" doc-level filter and field privileges,
     * i.e., no doc-level or field-level restrictions.
     */
    private DirectoryReader wrapWithDefaultDlsFls(DirectoryReader reader, ShardId shardId) throws IOException {
        return new DlsFlsFilterLeafReader.DlsFlsDirectoryReader(
            reader,
            FieldPrivileges.FlsRule.ALLOW_ALL,
            null,  // no doc-level restriction
            indexService,
            threadContext,
            clusterService,
            auditlog,
            FieldMasking.FieldMaskingRule.ALLOW_ALL,
            shardId,
            metaFields
        );
    }

    /**
     * Fallback to your existing logic to handle DLS/FLS if the index is not a resource index,
     * or if other conditions apply (like dlsFlsBaseContext usage, etc.).
     */
    private DirectoryReader wrapStandardDlsFls(
        PrivilegesEvaluationContext privilegesEvaluationContext,
        DirectoryReader reader,
        ShardId shardId,
        String indexName,
        boolean isAdmin
    ) throws IOException {
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
