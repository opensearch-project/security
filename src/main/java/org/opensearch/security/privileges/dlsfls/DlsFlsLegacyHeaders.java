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
package org.opensearch.security.privileges.dlsfls;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.Sets;

import org.opensearch.Version;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.transport.Transport;
import org.opensearch.transport.TransportRequest;

/**
 * Encapsulates functionality to provide transport headers with DLS/FLS information that need to be sent
 * to nodes which run on the legacy DLS/FLS implementation. This is only needed for mixed clusters.
 * See the attribute LEGACY_HEADERS_UNNECESSARY_AS_OF for the concrete version.
 * <p>
 * As soon as backward compat in mixed clusters is no longer required, this class should be removed.
 *
 */
public class DlsFlsLegacyHeaders {
    /**
     * Defines the first OpenSearch version which does not need the legacy headers
     * TODO this needs to be adapted if backported
     */
    static final Version LEGACY_HEADERS_UNNECESSARY_AS_OF = Version.V_3_0_0;

    /**
     * Returns true if the current cluster still contains nodes which are on an OpenSearch version which
     * requires the legacy DLS/FLS transport headers to be set. This still does not necessarily indicate that the
     * headers must be set, as this also depends on the concrete message that is being sent.
     */
    public static boolean possiblyRequired(ClusterService clusterService) {
        return !clusterService.state().nodes().getMinNodeVersion().onOrAfter(LEGACY_HEADERS_UNNECESSARY_AS_OF);
    }

    /**
     * Creates an DlsFlsLegacyHeaders instance and puts it asa transient into the thread context. This should be only called
     * if DlsFlsLegacyHeaders.possiblyRequired() returns true.
     * <p>
     * This method should be called in the DlsFlsRequestValve implementation, i.e., during action filtering.
     * Later, when transport messages are sent, performHeaderDecoration() should be called in the SecurityInterceptor
     * class.
     */
    public static void prepare(
        ThreadContext threadContext,
        PrivilegesEvaluationContext context,
        DlsFlsProcessedConfig config,
        Metadata metadata,
        boolean doFilterLevelDls
    ) throws PrivilegesEvaluationException {
        DlsFlsLegacyHeaders preparedHeaders = new DlsFlsLegacyHeaders(context, config, metadata, doFilterLevelDls);

        if (context.getRequest() instanceof ClusterSearchShardsRequest && HeaderHelper.isTrustedClusterRequest(threadContext)) {
            // Special case: Another cluster tries to initiate a cross cluster search and will talk directly to
            // the shards on our cluster. In this case, we do send the information as response headers.
            // The other cluster has code to correctly evaluate these response headers
            preparedHeaders.performResponseHeaderDecoration(threadContext);
        } else if (threadContext.getTransient(TRANSIENT_HEADER) == null) {
            // Normal case: No CCS involved
            threadContext.putTransient(TRANSIENT_HEADER, preparedHeaders);
        }
    }

    public static final String TRANSIENT_HEADER = ConfigConstants.OPENDISTRO_SECURITY_CONFIG_PREFIX + "dls_fls_legacy_headers";

    private final DlsFlsProcessedConfig config;

    private final String dlsHeader;
    private final String flsHeader;
    private final String fmHeader;

    public DlsFlsLegacyHeaders(
        PrivilegesEvaluationContext context,
        DlsFlsProcessedConfig config,
        Metadata metadata,
        boolean doFilterLevelDls
    ) throws PrivilegesEvaluationException {
        this.config = config;
        this.dlsHeader = !doFilterLevelDls ? getDlsHeader(context, config.getDocumentPrivileges(), metadata) : null;
        this.flsHeader = getFlsHeader(context, config.getFieldPrivileges(), metadata);
        this.fmHeader = getFieldMaskingHeader(context, config.getFieldMasking(), metadata);
    }

    /**
     * Writes the prepared DLS/FLS headers into the given map IF this method deems that it is necessary.
     * To be called when a transport message is sent to another node, i.e. in TransportInterceptor.interceptSender().
     */
    public void performHeaderDecoration(Transport.Connection connection, TransportRequest request, Map<String, String> headerMap) {

        if (connection.getVersion().onOrAfter(LEGACY_HEADERS_UNNECESSARY_AS_OF)) {
            // Target node is new enough -> no headers to be applied
            return;
        }

        if (request instanceof ActionRequest) {
            // The legacy implementation will create the information by itself in DlsFlsValve if an ActionRequest is received
            // Thus, if we have an ActionRequest, we do not need to get active either
            return;
        }

        if (dlsHeader != null) {
            headerMap.put(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, dlsHeader);
        }

        if (flsHeader != null) {
            headerMap.put(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, flsHeader);
        }

        if (fmHeader != null) {
            headerMap.put(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, fmHeader);
        }
    }

    /**
     * Only necessary for CCS in the case that another cluster checks out our shards with ClusterSearchShardsRequest:
     * In this case, we send the necessary information as response headers. The other cluster has code to evaluate
     * these response headers.
     */
    public void performResponseHeaderDecoration(ThreadContext threadContext) {
        if (dlsHeader != null) {
            threadContext.addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, dlsHeader);
        }

        if (flsHeader != null) {
            threadContext.addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, flsHeader);
        }

        if (fmHeader != null) {
            threadContext.addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, fmHeader);
        }
    }

    public String getDlsHeader() {
        return dlsHeader;
    }

    public String getFlsHeader() {
        return flsHeader;
    }

    public String getFmHeader() {
        return fmHeader;
    }

    private static String getDlsHeader(PrivilegesEvaluationContext context, DocumentPrivileges documentPrivileges, Metadata metadata)
        throws PrivilegesEvaluationException {
        IndexToRuleMap<DlsRestriction> dlsRestrictionMap = documentPrivileges.getRestrictions(
            context,
            metadata.indices().keySet(),
            documentPrivileges.unrestricted()
        );

        if (dlsRestrictionMap.isUnrestricted()) {
            return null;
        }

        Map<String, Set<String>> dlsQueriesByIndex = new HashMap<>();

        for (Map.Entry<String, DlsRestriction> entry : dlsRestrictionMap.getIndexMap().entrySet()) {
            // Do not include implicitly unrestricted rules (this is achieved by the != operator, an equals() would also catch explicit
            // unrestricted rules)
            if (entry.getValue() != documentPrivileges.unrestricted()) {
                dlsQueriesByIndex.put(
                    entry.getKey(),
                    entry.getValue().getQueries().stream().map(query -> query.getRenderedSource()).collect(Collectors.toSet())
                );
            }
        }

        return Base64Helper.serializeObject((Serializable) dlsQueriesByIndex);
    }

    private static String getFlsHeader(PrivilegesEvaluationContext context, FieldPrivileges fieldPrivileges, Metadata metadata)
        throws PrivilegesEvaluationException {
        IndexToRuleMap<FieldPrivileges.FlsRule> flsRuleMap = fieldPrivileges.getRestrictions(
            context,
            metadata.indices().keySet(),
            fieldPrivileges.unrestricted()
        );

        if (flsRuleMap.isUnrestricted()) {
            return null;
        }

        Map<String, Set<String>> flsFields = new HashMap<>();

        for (Map.Entry<String, FieldPrivileges.FlsRule> entry : flsRuleMap.getIndexMap().entrySet()) {
            // Do not include implicitly unrestricted rules (this is achieved by the != operator, an equals() would also catch explicit
            // unrestricted rules)
            if (entry.getValue() != fieldPrivileges.unrestricted()) {
                flsFields.put(entry.getKey(), Sets.newHashSet(entry.getValue().getSource()));
            }

        }

        return Base64Helper.serializeObject((Serializable) flsFields);
    }

    private static String getFieldMaskingHeader(PrivilegesEvaluationContext context, FieldMasking fieldMasking, Metadata metadata)
        throws PrivilegesEvaluationException {
        IndexToRuleMap<FieldMasking.FieldMaskingRule> fmRuleMap = fieldMasking.getRestrictions(
            context,
            metadata.indices().keySet(),
            fieldMasking.unrestricted()
        );

        if (fmRuleMap.isUnrestricted()) {
            return null;
        }

        Map<String, Set<String>> maskedFieldsMap = new HashMap<>();

        for (Map.Entry<String, FieldMasking.FieldMaskingRule> entry : fmRuleMap.getIndexMap().entrySet()) {
            // Do not include implicitly unrestricted rules (this is achieved by the != operator, an equals() would also catch explicit
            // unrestricted rules)
            if (entry.getValue() != fieldMasking.unrestricted()) {
                maskedFieldsMap.put(entry.getKey(), Sets.newHashSet(entry.getValue().getSource()));
            }
        }

        return Base64Helper.serializeObject((Serializable) maskedFieldsMap);
    }

}
