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
package org.opensearch.security.privileges;

import com.google.common.collect.ImmutableSet;

import org.opensearch.action.admin.cluster.health.ClusterHealthAction;
import org.opensearch.action.admin.cluster.node.stats.NodesStatsAction;
import org.opensearch.action.admin.cluster.state.ClusterStateAction;
import org.opensearch.action.admin.cluster.stats.ClusterStatsAction;
import org.opensearch.action.admin.indices.analyze.AnalyzeAction;
import org.opensearch.action.admin.indices.create.AutoCreateAction;
import org.opensearch.action.admin.indices.mapping.put.AutoPutMappingAction;
import org.opensearch.action.admin.indices.mapping.put.PutMappingAction;
import org.opensearch.action.admin.indices.refresh.RefreshAction;
import org.opensearch.action.admin.indices.refresh.TransportShardRefreshAction;
import org.opensearch.action.bulk.BulkAction;
import org.opensearch.action.bulk.TransportShardBulkAction;
import org.opensearch.action.delete.DeleteAction;
import org.opensearch.action.fieldcaps.FieldCapabilitiesAction;
import org.opensearch.action.get.GetAction;
import org.opensearch.action.get.MultiGetAction;
import org.opensearch.action.index.IndexAction;
import org.opensearch.action.main.MainAction;
import org.opensearch.action.search.ClearScrollAction;
import org.opensearch.action.search.MultiSearchAction;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchScrollAction;
import org.opensearch.action.termvectors.MultiTermVectorsAction;
import org.opensearch.action.termvectors.TermVectorsAction;
import org.opensearch.action.update.UpdateAction;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.UpdateByQueryAction;
import org.opensearch.security.support.ConfigConstants;

/**
 * This class lists so-called "well-known actions". These are taken into account when creating the pre-computed
 * data structures of the ActionPrivileges class. Thus, a very fast performance evaluation will be possible for
 * these actions. The trade-off is that each well-known action increases the heap footprint required by the data
 * structures. Thus, it makes sense to limit these actions to these which are really performance critical.
 */
public class WellKnownActions {
    public static final ImmutableSet<String> CLUSTER_ACTIONS = ImmutableSet.of(
        MultiGetAction.NAME,
        BulkAction.NAME,
        SearchScrollAction.NAME,
        MultiSearchAction.NAME,
        MultiTermVectorsAction.NAME,
        ClearScrollAction.NAME,
        MainAction.NAME,
        ClusterStatsAction.NAME,
        ClusterStateAction.NAME,
        ClusterHealthAction.NAME,
        NodesStatsAction.NAME
    );

    public static final ImmutableSet<String> INDEX_ACTIONS = ImmutableSet.of(
        IndexAction.NAME,
        GetAction.NAME,
        TermVectorsAction.NAME,
        DeleteAction.NAME,
        UpdateAction.NAME,
        SearchAction.NAME,
        UpdateByQueryAction.NAME,
        DeleteByQueryAction.NAME,
        TransportShardBulkAction.ACTION_NAME,
        PutMappingAction.NAME,
        AutoPutMappingAction.NAME,
        AnalyzeAction.NAME,
        AutoCreateAction.NAME,
        RefreshAction.NAME,
        TransportShardRefreshAction.NAME,
        FieldCapabilitiesAction.NAME
    );

    /**
     * Compare https://github.com/opensearch-project/security/pull/2887
     */
    public static final ImmutableSet<String> EXPLICITLY_REQUIRED_INDEX_ACTIONS = ImmutableSet.of(ConfigConstants.SYSTEM_INDEX_PERMISSION);
}
