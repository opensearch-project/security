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
package org.opensearch.security.privileges.actionlevel.nextgen;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.admin.indices.create.AutoCreateAction;
import org.opensearch.action.admin.indices.create.CreateIndexAction;
import org.opensearch.action.admin.indices.mapping.put.AutoPutMappingAction;
import org.opensearch.action.admin.indices.mapping.put.PutMappingAction;
import org.opensearch.action.admin.indices.template.delete.DeleteComposableIndexTemplateAction;
import org.opensearch.action.admin.indices.template.delete.DeleteIndexTemplateAction;
import org.opensearch.action.admin.indices.template.get.GetComposableIndexTemplateAction;
import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesAction;
import org.opensearch.action.admin.indices.template.post.SimulateIndexTemplateAction;
import org.opensearch.action.admin.indices.template.post.SimulateTemplateAction;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateAction;
import org.opensearch.action.admin.indices.upgrade.post.UpgradeAction;
import org.opensearch.action.admin.indices.upgrade.post.UpgradeSettingsAction;
import org.opensearch.action.search.GetAllPitsAction;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.script.mustache.MultiSearchTemplateAction;
import org.opensearch.script.mustache.RenderSearchTemplateAction;
import org.opensearch.security.privileges.actionlevel.WellKnownActions;

/**
 * This class encapsulates some logic and configuration related to action names used in the PrivilegesEvaluator.
 * It exposes a number of config options which affect the way action names are treated. See below.
 * <p>
 * The purpose of these settings is mainly to have an emergency measure in case an action is incorrectly handled
 * in PrivilegesEvaluator. That's why they are just documented in this class, but not in the user docs.
 */
class ActionConfiguration {

    /**
     * This setting expects a list of action names (like "indices:data/read/search"); all action names
     * that are listed here will be treated as "cluster privileges" by the PrivilegesEvaluator.
     * That means privileges for these actions must be specified in the cluster_privileges section in roles.yml.
     */
    public static Setting<List<String>> FORCE_AS_CLUSTER_ACTIONS = Setting.listSetting(
        "plugins.security.privileges_evaluation.actions.force_as_cluster_actions",
        Collections.emptyList(),
        Function.identity(),
        Setting.Property.NodeScope
    );

    /**
     * This setting expects a list of action mapping strings; these need to be formatted like
     * "indices:data/write/bulk>indices:data/write/index". Whenever PrivilegesEvaluator receives an action called
     * X, it will check in the mapping wheter X is mapped to Y. If so, it will check privileges for Y.
     */
    public static Setting<List<String>> MAP_ACTION_NAMES = Setting.listSetting(
        "plugins.security.privileges_evaluation.actions.map_action_names",
        Collections.emptyList(),
        Function.identity(),
        Setting.Property.NodeScope
    );

    /**
     * A list of action names which will be always denied by PrivilegesEvaluator, regardless of any
     * other setting. The only way to execute such actions will be using a super admin certificate.
     */
    public static Setting<List<String>> UNIVERSALLY_DENIED_ACTIONS = Setting.listSetting(
        "plugins.security.privileges_evaluation.actions.universally_denied_actions",
        Collections.emptyList(),
        Function.identity(),
        Setting.Property.NodeScope
    );

    private static final Logger log = LogManager.getLogger(ActionConfiguration.class);

    private final ImmutableMap<String, String> actionToActionMap;
    private final ImmutableSet<String> explicitIndexActions;
    private final ImmutableSet<String> clusterActions;
    private final ImmutableSet<String> universallyDeniedActions;

    ActionConfiguration(Settings settings) {
        this.actionToActionMap = buildActionToActionMap(settings);
        this.explicitIndexActions = buildExplicitIndexActionSet(settings);
        this.clusterActions = buildClusterActionSet(settings);
        this.universallyDeniedActions = ImmutableSet.copyOf(UNIVERSALLY_DENIED_ACTIONS.get(settings));
    }

    /**
     * Checks the action mapping and normalizes the given action name. In most cases, this will just return the
     * original action name.
     */
    String normalize(String action) {
        String mapped = this.actionToActionMap.get(action);
        if (mapped != null) {
            return mapped;
        } else {
            return action;
        }
    }

    /**
     * Returns true if the given action is supposed to be a cluster action according to the configuration.
     */
    boolean isClusterPermission(String action) {
        if (this.explicitIndexActions.contains(action)) {
            return false;
        } else if (this.clusterActions.contains(action)) {
            return true;
        } else {
            // TODO maybe move to "indices:" prefix
            return action.startsWith("cluster:")
                || action.startsWith("indices:admin/template/")
                || action.startsWith("indices:admin/index_template/");
        }
    }

    boolean isUniversallyDenied(String action) {
        return this.universallyDeniedActions.contains(action);
    }

    private static ImmutableMap<String, String> buildActionToActionMap(Settings settings) {
        ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();

        // The following mappings were originally defined at
        // https://github.com/opensearch-project/security/blob/eb7153d772e9e00d49d9cb5ffafb33b5f02399fc/src/main/java/org/opensearch/security/privileges/PrivilegesEvaluator.java#L392
        builder.put(UpgradeSettingsAction.NAME, UpgradeAction.NAME);
        builder.put(AutoCreateAction.NAME, CreateIndexAction.NAME);
        builder.put(AutoPutMappingAction.NAME, PutMappingAction.NAME);

        for (String entry : MAP_ACTION_NAMES.get(settings)) {
            String[] parts = entry.split(">");
            if (parts.length == 2) {
                builder.put(parts[0], parts[1]);
            } else {
                log.error("Invalid value for {}: {}", MAP_ACTION_NAMES.getKey(), entry);
            }
        }

        return builder.build();
    }

    private static ImmutableSet<String> buildClusterActionSet(Settings settings) {
        ImmutableSet.Builder<String> builder = ImmutableSet.builder();

        // A couple of "indices:" actions are considered as cluster level privileges for a number of different reasons.
        // See below for details
        builder.addAll(WellKnownActions.CLUSTER_ACTIONS);

        // The _msearch action triggers under the hood an additional _search action; thus it is sufficient to check index specific
        // privileges on the _search level
        builder.add(MultiSearchTemplateAction.NAME);

        // The _reindex action triggers under the hood _search and _bulk actions; thus, index privileges can be checked on these levels
        builder.add(ReindexAction.NAME);

        // The _render/template action actually does not operate on indices at all
        builder.add(RenderSearchTemplateAction.NAME);

        // The _search/point_in_time/_all action provides no possibility to specify/reduce indices. Thus, it should be a cluster action
        builder.add(GetAllPitsAction.NAME);

        // The index template and composable template actions do not specify indices, but specify patterns for potentially non-existing
        // indices.
        // This makes it difficult (or rather impossible) to match these against the privilege definition index patterns.
        // Thus, we treat these as cluster privileges
        builder.add(PutIndexTemplateAction.NAME);
        builder.add(DeleteIndexTemplateAction.NAME);
        builder.add(GetIndexTemplatesAction.NAME);
        builder.add(PutComposableIndexTemplateAction.NAME);
        builder.add(DeleteComposableIndexTemplateAction.NAME);
        builder.add(GetComposableIndexTemplateAction.NAME);
        builder.add(SimulateIndexTemplateAction.NAME);
        builder.add(SimulateTemplateAction.NAME);

        builder.addAll(FORCE_AS_CLUSTER_ACTIONS.get(settings));
        return builder.build();
    }

    ImmutableSet<String> buildExplicitIndexActionSet(Settings settings) {
        Set<String> builder = new HashSet<>(WellKnownActions.INDEX_ACTIONS);
        builder.removeAll(FORCE_AS_CLUSTER_ACTIONS.get(settings));
        return ImmutableSet.copyOf(builder);
    }
}
