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

import java.lang.reflect.Field;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.StreamSupport;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.BooleanClause.Occur;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.ConstantScoreQuery;
import org.apache.lucene.util.BytesRef;

import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.RealtimeRequest;
import org.opensearch.action.admin.indices.shrink.ResizeRequest;
import org.opensearch.action.bulk.BulkAction;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.search.MultiSearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.ParsedQuery;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.script.mustache.RenderSearchTemplateAction;
import org.opensearch.search.DocValueFormat;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.AggregatorFactories;
import org.opensearch.search.aggregations.BucketOrder;
import org.opensearch.search.aggregations.InternalAggregation;
import org.opensearch.search.aggregations.InternalAggregations;
import org.opensearch.search.aggregations.bucket.MultiBucketsAggregation;
import org.opensearch.search.aggregations.bucket.sampler.DiversifiedAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.InternalTerms;
import org.opensearch.search.aggregations.bucket.terms.SignificantTermsAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.StringTerms;
import org.opensearch.search.aggregations.bucket.terms.StringTerms.Bucket;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.internal.SearchContext;
import org.opensearch.search.query.QuerySearchResult;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.privileges.DocumentAllowList;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.privileges.dlsfls.DlsFlsBaseContext;
import org.opensearch.security.privileges.dlsfls.DlsFlsLegacyHeaders;
import org.opensearch.security.privileges.dlsfls.DlsFlsProcessedConfig;
import org.opensearch.security.privileges.dlsfls.DlsRestriction;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.privileges.dlsfls.IndexToRuleMap;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.resources.ResourceSharingDlsUtils;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.support.SecuritySettings;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.security.support.ConfigConstants.SECURITY_DLS_WRITE_BLOCKED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_DLS_WRITE_BLOCKED_ENABLED_DEFAULT;

public class DlsFlsValveImpl implements DlsFlsRequestValve {

    private static final String MAP_EXECUTION_HINT = "map";
    private static final Logger log = LogManager.getLogger(DlsFlsValveImpl.class);

    private final Client nodeClient;
    private final ClusterService clusterService;
    private final ThreadContext threadContext;
    private final Mode mode;
    private final NamedXContentRegistry namedXContentRegistry;
    private final DlsFlsBaseContext dlsFlsBaseContext;
    private final AtomicReference<DlsFlsProcessedConfig> dlsFlsProcessedConfig = new AtomicReference<>();
    private final FieldMasking.Config fieldMaskingConfig;
    private final Settings settings;
    private final AdminDNs adminDNs;
    private final OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting;
    private final ResourcePluginInfo resourcePluginInfo;
    private volatile boolean dlsWriteBlockedEnabled;

    public DlsFlsValveImpl(
        Settings settings,
        Client nodeClient,
        ClusterService clusterService,
        NamedXContentRegistry namedXContentRegistry,
        ThreadPool threadPool,
        DlsFlsBaseContext dlsFlsBaseContext,
        AdminDNs adminDNs,
        ResourcePluginInfo resourcePluginInfo,
        OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting
    ) {
        super();
        this.nodeClient = nodeClient;
        this.clusterService = clusterService;
        this.threadContext = threadPool.getThreadContext();
        this.mode = Mode.get(settings);
        this.namedXContentRegistry = namedXContentRegistry;
        this.fieldMaskingConfig = FieldMasking.Config.fromSettings(settings);
        this.dlsFlsBaseContext = dlsFlsBaseContext;
        this.settings = settings;
        this.adminDNs = adminDNs;
        this.resourcePluginInfo = resourcePluginInfo;

        clusterService.addListener(event -> {
            DlsFlsProcessedConfig config = dlsFlsProcessedConfig.get();

            if (config != null) {
                config.updateClusterStateMetadataAsync(clusterService::state, threadPool);
            }
        });
        this.dlsWriteBlockedEnabled = settings.getAsBoolean(SECURITY_DLS_WRITE_BLOCKED, SECURITY_DLS_WRITE_BLOCKED_ENABLED_DEFAULT);
        if (clusterService.getClusterSettings() != null) {
            clusterService.getClusterSettings().addSettingsUpdateConsumer(SecuritySettings.DLS_WRITE_BLOCKED, newDlsWriteBlockedEnabled -> {
                dlsWriteBlockedEnabled = newDlsWriteBlockedEnabled;
            });
        }
        this.resourceSharingEnabledSetting = resourceSharingEnabledSetting;
    }

    /**
     *
     * @param listener
     * @return false on error
     */
    @Override
    public boolean invoke(PrivilegesEvaluationContext context, final ActionListener<?> listener) {
        if (!isApplicable(context.getAction())) {
            return true;
        }

        UserSubjectImpl userSubject = (UserSubjectImpl) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER);
        if (userSubject != null && adminDNs.isAdmin(userSubject.getUser())) {
            return true;
        }
        OptionallyResolvedIndices resolved = context.getResolvedIndices();
        ActionRequest request = context.getRequest();
        if (HeaderHelper.isInternalOrPluginRequest(threadContext)) {
            if (resourceSharingEnabledSetting.getDynamicSettingValue()
                && request instanceof SearchRequest
                && resolved instanceof ResolvedIndices resolvedIndices) {
                Set<String> protectedIndices = resourcePluginInfo.getResourceIndicesForProtectedTypes();
                WildcardMatcher resourceIndicesMatcher = WildcardMatcher.from(protectedIndices);
                Set<String> resolvedIndexNames = resolvedIndices.local().namesOfIndices(context.clusterState());
                if (resourceIndicesMatcher.matchAll(resolvedIndexNames)) {
                    IndexToRuleMap<DlsRestriction> sharedResourceMap = ResourceSharingDlsUtils.resourceRestrictions(
                        namedXContentRegistry,
                        resolvedIndexNames,
                        userSubject.getUser()
                    );

                    return DlsFilterLevelActionHandler.handle(
                        context,
                        sharedResourceMap,
                        listener,
                        nodeClient,
                        clusterService,
                        OpenSearchSecurityPlugin.GuiceHolder.getIndicesService(),
                        threadContext
                    );
                }
            }
            return true;
        }
        DlsFlsProcessedConfig config = this.dlsFlsProcessedConfig.get();

        DocumentAllowList documentAllowList = DocumentAllowList.get(threadContext);

        if (resolved instanceof ResolvedIndices resolvedIndices
            && resolvedIndices.local()
                .namesOfIndices(context.clusterState())
                .stream()
                .anyMatch(index -> documentAllowList.isAllowed(index, "*"))) {
            // The documentAllowList is needed here for Dashboards multi tenancy which can redirect index accesses to indices for which no
            // normal index privileges are present
            // If we would not use the documentAllowList here, the index would appear to be protected

            if (resolvedIndices.local().names().size() == 1) {
                return true;
            }
        }

        try {
            boolean hasDlsRestrictions = !config.getDocumentPrivileges().isUnrestricted(context, resolved);
            boolean hasFlsRestrictions = !config.getFieldPrivileges().isUnrestricted(context, resolved);
            boolean hasFieldMasking = !config.getFieldMasking().isUnrestricted(context, resolved);

            if (!hasDlsRestrictions && !hasFlsRestrictions && !hasFieldMasking) {
                return true;
            }

            if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE) != null) {
                if (log.isDebugEnabled()) {
                    log.debug(
                        "DLS is already done for: {}",
                        threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE)
                    );
                }

                return true;
            }

            IndexToRuleMap<DlsRestriction> dlsRestrictionMap = null;
            boolean doFilterLevelDls;

            if (mode == Mode.FILTER_LEVEL) {
                doFilterLevelDls = true;
                dlsRestrictionMap = config.getDocumentPrivileges().getRestrictions(context, resolved.local().names(context.clusterState()));
            } else if (mode == Mode.LUCENE_LEVEL) {
                doFilterLevelDls = false;
            } else { // mode == Mode.ADAPTIVE
                Mode modeByHeader = getDlsModeHeader();
                dlsRestrictionMap = config.getDocumentPrivileges().getRestrictions(context, resolved.local().names(context.clusterState()));

                if (modeByHeader == Mode.FILTER_LEVEL) {
                    doFilterLevelDls = true;
                    log.debug("Doing filter-level DLS due to header");
                } else {
                    doFilterLevelDls = dlsRestrictionMap.containsAny(DlsRestriction::containsTermLookupQuery);

                    if (doFilterLevelDls) {
                        setDlsModeHeader(Mode.FILTER_LEVEL);
                        log.debug("Doing filter-level DLS because the query contains a TLQ");
                    } else {
                        log.debug("Doing lucene-level DLS because the query does not contain a TLQ");
                    }
                }
            }

            if (DlsFlsLegacyHeaders.possiblyRequired(clusterService)) {
                DlsFlsLegacyHeaders.prepare(threadContext, context, config, clusterService.state().metadata(), doFilterLevelDls);
            }

            if (request instanceof RealtimeRequest) {
                ((RealtimeRequest) request).realtime(Boolean.FALSE);
            }

            if (request instanceof SearchRequest) {

                SearchRequest searchRequest = ((SearchRequest) request);

                // When we encounter a terms or sampler aggregation with masked fields activated we forcibly
                // need to switch off global ordinals because field masking can break ordering
                // CS-SUPPRESS-SINGLE: RegexpSingleline Ignore term inside of url
                // https://www.elastic.co/guide/en/elasticsearch/reference/master/eager-global-ordinals.html#_avoiding_global_ordinal_loading
                // CS-ENFORCE-SINGLE
                if (hasFieldMasking) {

                    if (searchRequest.source() != null && searchRequest.source().aggregations() != null) {
                        for (AggregationBuilder aggregationBuilder : searchRequest.source().aggregations().getAggregatorFactories()) {
                            if (aggregationBuilder instanceof TermsAggregationBuilder) {
                                ((TermsAggregationBuilder) aggregationBuilder).executionHint(MAP_EXECUTION_HINT);
                            }

                            if (aggregationBuilder instanceof SignificantTermsAggregationBuilder) {
                                ((SignificantTermsAggregationBuilder) aggregationBuilder).executionHint(MAP_EXECUTION_HINT);
                            }

                            if (aggregationBuilder instanceof DiversifiedAggregationBuilder) {
                                ((DiversifiedAggregationBuilder) aggregationBuilder).executionHint(MAP_EXECUTION_HINT);
                            }
                        }
                    }
                }

                if (!hasFlsRestrictions && !hasDlsRestrictions && searchRequest.source().aggregations() != null) {

                    boolean cacheable = true;

                    for (AggregationBuilder af : searchRequest.source().aggregations().getAggregatorFactories()) {

                        if (!af.getType().equals("cardinality") && !af.getType().equals("count")) {
                            cacheable = false;
                            continue;
                        }

                        StringBuilder sb = new StringBuilder();

                        if (searchRequest.source() != null) {
                            sb.append(Strings.toString(MediaTypeRegistry.JSON, searchRequest.source()) + System.lineSeparator());
                        }

                        sb.append(Strings.toString(MediaTypeRegistry.JSON, af) + System.lineSeparator());

                        LogManager.getLogger("debuglogger").error(sb.toString());

                    }

                    if (!cacheable) {
                        searchRequest.requestCache(Boolean.FALSE);
                    } else {
                        LogManager.getLogger("debuglogger")
                            .error(
                                "Shard requestcache enabled for "
                                    + (searchRequest.source() == null
                                        ? "<NULL>"
                                        : Strings.toString(MediaTypeRegistry.JSON, searchRequest.source()))
                            );
                    }

                } else {
                    searchRequest.requestCache(Boolean.FALSE);
                }
            }

            if (request instanceof UpdateRequest) {
                listener.onFailure(new OpenSearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated"));
                return false;
            }

            if (request instanceof BulkShardRequest) {
                for (BulkItemRequest inner : ((BulkShardRequest) request).items()) {
                    if (dlsWriteBlockedEnabled) {
                        listener.onFailure(
                            new OpenSearchSecurityException(
                                inner.request().getClass().getSimpleName()
                                    + " is not supported when FLS or DLS or Fieldmasking is activated"
                            )
                        );
                        return false;
                    } else {
                        if (inner.request() instanceof UpdateRequest) {
                            listener.onFailure(
                                new OpenSearchSecurityException("Update is not supported when FLS or DLS or Fieldmasking is activated")
                            );
                            return false;
                        }
                    }
                }
            }

            if (request instanceof ResizeRequest) {
                listener.onFailure(new OpenSearchSecurityException("Resize is not supported when FLS or DLS or Fieldmasking is activated"));
                return false;
            }

            if (context.getAction().contains("plugins/replication")) {
                listener.onFailure(
                    new OpenSearchSecurityException(
                        "Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated",
                        RestStatus.FORBIDDEN
                    )
                );
                return false;
            }

            if (hasDlsRestrictions) {
                if (request instanceof SearchRequest) {

                    final SearchSourceBuilder source = ((SearchRequest) request).source();
                    if (source != null) {
                        AggregatorFactories.Builder aggregations = source.aggregations();
                        if (aggregations != null) {
                            for (AggregationBuilder factory : aggregations.getAggregatorFactories()) {
                                if (factory instanceof TermsAggregationBuilder && ((TermsAggregationBuilder) factory).minDocCount() == 0) {
                                    listener.onFailure(new OpenSearchException("min_doc_count 0 is not supported when DLS is activated"));
                                    return false;
                                }
                            }
                        }

                        if (source.profile()) {
                            listener.onFailure(new OpenSearchSecurityException("Profiling is not supported when DLS is activated"));
                            return false;
                        }

                    }
                }
            }

            if (doFilterLevelDls && hasDlsRestrictions) {
                return DlsFilterLevelActionHandler.handle(
                    context,
                    dlsRestrictionMap,
                    listener,
                    nodeClient,
                    clusterService,
                    OpenSearchSecurityPlugin.GuiceHolder.getIndicesService(),
                    threadContext
                );
            } else {
                return true;
            }

        } catch (PrivilegesEvaluationException e) {
            log.error("Error while evaluating DLS/FLS privileges", e);
            listener.onFailure(new OpenSearchSecurityException("Error while evaluating DLS/FLS privileges"));
            return false;
        } catch (RuntimeException e) {
            log.error(e);
            throw e;
        }
    }

    @Override
    public void handleSearchContext(SearchContext searchContext, ThreadPool threadPool, NamedXContentRegistry namedXContentRegistry) {
        try {
            String index = searchContext.indexShard().indexSettings().getIndex().getName();

            if (log.isTraceEnabled()) {
                log.trace("handleSearchContext(); index: {}", index);
            }

            if (searchContext.suggest() != null) {
                return;
            }

            if (dlsFlsBaseContext.isDlsDoneOnFilterLevel() || mode == Mode.FILTER_LEVEL) {
                // For filter level DLS, the query was already modified to include the DLS restrictions.
                // Thus, we can exist here early.
                log.trace("handleSearchContext(): DLS is done on the filter level; no further handling necessary");
                return;
            }

            if (dlsFlsBaseContext.isPrivilegedConfigRequest()) {
                // Requests with the header OPENDISTRO_SECURITY_CONF_REQUEST_HEADER set bypass any access controls.
                // This follows the logic from
                // https://github.com/opensearch-project/security/blob/1c898dcc4a92e8d4aa8b18c3fed761b5f6e52d4f/src/main/java/org/opensearch/security/filter/SecurityFilter.java#L209
                // In the old DLS/FLS implementation, that check in SecurityFilter would also affect this code.
                // Now it does not any more, thus we need this additional check here.
                return;
            }

            PrivilegesEvaluationContext privilegesEvaluationContext = this.dlsFlsBaseContext.getPrivilegesEvaluationContext();
            if (privilegesEvaluationContext == null) {
                return;
            }
            DlsFlsProcessedConfig config = this.dlsFlsProcessedConfig.get();

            DlsRestriction dlsRestriction = config.getDocumentPrivileges().getRestriction(privilegesEvaluationContext, index);

            if (log.isTraceEnabled()) {
                log.trace("handleSearchContext(); index: {}; dlsRestriction: {}", index, dlsRestriction);
            }

            DocumentAllowList documentAllowList = DocumentAllowList.get(threadContext);

            if (documentAllowList.isEntryForIndexPresent(index)) {
                // The documentAllowList is needed for two cases:
                // - DLS rules which use "term lookup queries" and thus need to access indices for which no privileges are present
                // - Dashboards multi tenancy which can redirect index accesses to indices for which no normal index privileges are present

                if (!dlsRestriction.isUnrestricted() && documentAllowList.isAllowed(index, "*")) {
                    dlsRestriction = DlsRestriction.NONE;
                    log.debug("Lifting DLS for {} due to present document allowlist", index);
                }
            }

            // Restrict access for star tree index if there are any DLS/FLS/field masking restrictions
            if (searchContext.getQueryShardContext().getStarTreeQueryContext() != null) {
                boolean flsUnrestricted = config.getFieldPrivileges().isUnrestricted(privilegesEvaluationContext, index);
                boolean fieldMaskingUnrestricted = config.getFieldMasking().isUnrestricted(privilegesEvaluationContext, index);
                if (!dlsRestriction.isUnrestricted() || !flsUnrestricted || !fieldMaskingUnrestricted) {
                    searchContext.getQueryShardContext().setStarTreeQueryContext(null);
                }
            }

            if (!dlsRestriction.isUnrestricted()) {
                if (mode == Mode.ADAPTIVE && dlsRestriction.containsTermLookupQuery()) {
                    // Special case for scroll operations:
                    // Normally, the check dlsFlsBaseContext.isDlsDoneOnFilterLevel() already aborts early if DLS filter level mode
                    // has been activated. However, this is not the case for scroll operations, as these lose the thread context value
                    // on which dlsFlsBaseContext.isDlsDoneOnFilterLevel() is based on. Thus, we need to check here again the deeper
                    // conditions.
                    log.trace("DlsRestriction: contains TLQ.");
                    return;
                }

                assert searchContext.parsedQuery() != null;

                BooleanQuery.Builder queryBuilder = dlsRestriction.toBooleanQueryBuilder(
                    searchContext.getQueryShardContext(),
                    (q) -> new ConstantScoreQuery(q)
                );

                queryBuilder.add(searchContext.parsedQuery().query(), Occur.MUST);

                searchContext.parsedQuery(new ParsedQuery(queryBuilder.build()));
                searchContext.preProcess(true);
            }
        } catch (Exception e) {
            log.error("Error in handleSearchContext()", e);
            throw new RuntimeException("Error evaluating dls for a search query: " + e, e);
        }
    }

    @Override
    public void onQueryPhase(QuerySearchResult queryResult) {
        InternalAggregations aggregations = queryResult.aggregations().expand();
        assert aggregations != null;

        queryResult.aggregations(
            InternalAggregations.from(
                StreamSupport.stream(aggregations.spliterator(), false)
                    .map(aggregation -> aggregateBuckets((InternalAggregation) aggregation))
                    .collect(ImmutableList.toImmutableList())
            )
        );
    }

    @Override
    public DlsFlsProcessedConfig getCurrentConfig() {
        return dlsFlsProcessedConfig.get();
    }

    @Override
    public boolean hasFlsOrFieldMasking(String index) throws PrivilegesEvaluationException {
        PrivilegesEvaluationContext privilegesEvaluationContext = this.dlsFlsBaseContext.getPrivilegesEvaluationContext();
        if (privilegesEvaluationContext == null) {
            return false;
        }

        DlsFlsProcessedConfig config = this.dlsFlsProcessedConfig.get();
        return !config.getFieldPrivileges().isUnrestricted(privilegesEvaluationContext, index)
            || !config.getFieldMasking().isUnrestricted(privilegesEvaluationContext, index);
    }

    @Override
    public boolean hasFieldMasking(String index) throws PrivilegesEvaluationException {
        PrivilegesEvaluationContext privilegesEvaluationContext = this.dlsFlsBaseContext.getPrivilegesEvaluationContext();
        if (privilegesEvaluationContext == null) {
            return false;
        }

        DlsFlsProcessedConfig config = this.dlsFlsProcessedConfig.get();
        return !config.getFieldMasking().isUnrestricted(privilegesEvaluationContext, index);
    }

    @Override
    public boolean isFieldAllowed(String index, String field, PrivilegesEvaluationContext ctx) throws PrivilegesEvaluationException {
        if (ctx == null) {
            return true;
        }

        DlsFlsProcessedConfig config = this.dlsFlsProcessedConfig.get();
        return config.getFieldPrivileges().getRestriction(ctx, index).isAllowedRecursive(field);
    }

    private static boolean isApplicable(String action) {
        if (action.startsWith("cluster:")) {
            // Cluster actions are generally not applicable
            return false;
        }
        if (action.startsWith("indices:admin/template/") || action.startsWith("indices:admin/index_template/")) {
            // Template related actions can be safely executed without DLS/FLS applied
            return false;
        }
        if (action.equals(BulkAction.NAME)) {
            // We do not need to consider top-level bulk actions; we check the shard level later
            return false;
        }
        if (action.equals(MultiSearchAction.NAME)) {
            // We do not need to consider top-level multi search actions; we check the search actions that are executed later
            return false;
        }
        if (action.equals(RenderSearchTemplateAction.NAME)) {
            // Template related actions trigger further sub actions which we check later
            return false;
        }
        if (action.equals(ReindexAction.NAME)) {
            // Reindex actions break apart in search and bulk actions; we will handle on these levels
            return false;
        }
        return true;
    }

    private static InternalAggregation aggregateBuckets(InternalAggregation aggregation) {
        if (aggregation instanceof StringTerms) {
            StringTerms stringTerms = (StringTerms) aggregation;
            List<Bucket> buckets = stringTerms.getBuckets();
            if (buckets.size() > 1) {
                buckets = mergeBuckets(buckets, StringTermsGetter.getReduceOrder(stringTerms).comparator());
                aggregation = stringTerms.create(buckets);
            }
        }
        return aggregation;
    }

    private static List<StringTerms.Bucket> mergeBuckets(
        List<StringTerms.Bucket> buckets,
        Comparator<MultiBucketsAggregation.Bucket> comparator
    ) {
        if (log.isDebugEnabled()) {
            log.debug("Merging buckets: {}", buckets.stream().map(b -> b.getKeyAsString()).collect(ImmutableList.toImmutableList()));
        }
        buckets.sort(comparator);
        BucketMerger merger = new BucketMerger(comparator, buckets.size());
        buckets.stream().forEach(merger);
        buckets = merger.getBuckets();

        if (log.isDebugEnabled()) {
            log.debug("New buckets: {}", buckets.stream().map(b -> b.getKeyAsString()).collect(ImmutableList.toImmutableList()));
        }
        return buckets;
    }

    private void setDlsModeHeader(Mode mode) {
        String modeString = mode.name();

        if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER) != null) {
            if (!modeString.equals(threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER))) {
                log.warn(
                    "Cannot update DLS mode to "
                        + mode
                        + "; current: "
                        + threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER)
                );
            }
        } else {
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER, modeString);
        }
    }

    private Mode getDlsModeHeader() {
        String modeString = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER);

        if (modeString != null) {
            return Mode.valueOf(modeString);
        } else {
            return null;
        }
    }

    private static class BucketMerger implements Consumer<Bucket> {
        private Comparator<MultiBucketsAggregation.Bucket> comparator;
        private StringTerms.Bucket bucket = null;
        private int mergeCount;
        private long mergedDocCount;
        private long mergedDocCountError;
        private boolean showDocCountError = true;
        private final ImmutableList.Builder<StringTerms.Bucket> builder;

        BucketMerger(Comparator<MultiBucketsAggregation.Bucket> comparator, int size) {
            this.comparator = Objects.requireNonNull(comparator);
            builder = ImmutableList.builderWithExpectedSize(size);
        }

        private void finalizeBucket() {
            if (mergeCount == 1) {
                builder.add(this.bucket);
            } else {
                builder.add(
                    new StringTerms.Bucket(
                        StringTermsGetter.getTerm(bucket),
                        mergedDocCount,
                        (InternalAggregations) bucket.getAggregations(),
                        showDocCountError,
                        mergedDocCountError,
                        StringTermsGetter.getDocValueFormat(bucket)
                    )
                );
            }
        }

        private void merge(StringTerms.Bucket bucket) {
            if (this.bucket != null && (bucket == null || comparator.compare(this.bucket, bucket) != 0)) {
                finalizeBucket();
                this.bucket = null;
                mergeCount = 0;
                mergedDocCount = 0;
                mergedDocCountError = 0;
                showDocCountError = true;
            }
        }

        public List<StringTerms.Bucket> getBuckets() {
            merge(null);
            return builder.build();
        }

        @Override
        public void accept(StringTerms.Bucket bucket) {
            merge(bucket);
            mergeCount++;
            mergedDocCount += bucket.getDocCount();
            if (showDocCountError) {
                try {
                    mergedDocCountError += bucket.getDocCountError();
                } catch (IllegalStateException e) {
                    showDocCountError = false;
                }
            }
            this.bucket = bucket;
        }
    }

    private static class StringTermsGetter {
        private static final Field REDUCE_ORDER = getField(InternalTerms.class, "reduceOrder");
        private static final Field TERM_BYTES = getField(StringTerms.Bucket.class, "termBytes");
        private static final Field FORMAT = getField(InternalTerms.Bucket.class, "format");

        private StringTermsGetter() {}

        private static <T> Field getFieldPrivileged(Class<T> cls, String name) {
            try {
                final Field field = cls.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException | SecurityException e) {
                log.error("Failed to get class {} declared field {}", cls.getSimpleName(), name, e);
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    throw new RuntimeException(e);
                }
            }
        }

        private static <T> Field getField(Class<T> cls, String name) {
            return AccessController.doPrivileged(() -> getFieldPrivileged(cls, name));
        }

        @SuppressWarnings("unchecked")
        private static <T, C> T getFieldValue(Field field, C c) {
            try {
                return (T) field.get(c);
            } catch (IllegalArgumentException | IllegalAccessException e) {
                log.error("Exception while getting value {} of class {}", field.getName(), c.getClass().getSimpleName(), e);
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    throw new RuntimeException(e);
                }
            }
        }

        public static BucketOrder getReduceOrder(StringTerms stringTerms) {
            return getFieldValue(REDUCE_ORDER, stringTerms);
        }

        public static BytesRef getTerm(StringTerms.Bucket bucket) {
            return getFieldValue(TERM_BYTES, bucket);
        }

        public static DocValueFormat getDocValueFormat(StringTerms.Bucket bucket) {
            return getFieldValue(FORMAT, bucket);
        }
    }

    public static enum Mode {
        ADAPTIVE,
        LUCENE_LEVEL,
        FILTER_LEVEL;

        static Mode get(Settings settings) {
            String modeString = settings.get(ConfigConstants.SECURITY_DLS_MODE);

            if ("adaptive".equalsIgnoreCase(modeString)) {
                return Mode.ADAPTIVE;
            } else if ("lucene_level".equalsIgnoreCase(modeString)) {
                return Mode.LUCENE_LEVEL;
            } else if ("filter_level".equalsIgnoreCase(modeString)) {
                return Mode.FILTER_LEVEL;
            } else {
                return Mode.ADAPTIVE;
            }
        }
    }

    public void updateConfiguration(SecurityDynamicConfiguration<RoleV7> rolesConfiguration) {
        try {
            if (rolesConfiguration != null) {
                DlsFlsProcessedConfig oldConfig = this.dlsFlsProcessedConfig.getAndSet(
                    new DlsFlsProcessedConfig(
                        DynamicConfigFactory.addStatics(rolesConfiguration.clone()),
                        clusterService.state().metadata().getIndicesLookup(),
                        namedXContentRegistry,
                        settings,
                        fieldMaskingConfig
                    )
                );

                if (oldConfig != null) {
                    oldConfig.shutdown();
                }
            }
        } catch (Exception e) {
            log.error("Error while updating DLS/FLS configuration with {}", rolesConfiguration, e);
        }
    }
}
