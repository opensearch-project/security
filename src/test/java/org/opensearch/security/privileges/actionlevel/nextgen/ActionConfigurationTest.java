/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.privileges.actionlevel.nextgen;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import org.opensearch.action.admin.indices.template.put.PutIndexTemplateAction;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ActionConfigurationTest {

    private static final String DESCRIBE_INDEX_SETTINGS = "indices:monitor/settings/describe";

    @Test
    public void indexSettingsDescribeIsAClusterPermission() {
        ActionConfiguration configuration = new ActionConfiguration(Settings.EMPTY);

        // Names no index, so it is evaluated all-or-nothing like the template actions.
        assertTrue(configuration.isClusterPermission(DESCRIBE_INDEX_SETTINGS));
        assertTrue(configuration.isClusterPermission(PutIndexTemplateAction.NAME));

        // Its neighbour reads configured values of concrete indices and stays an index permission.
        assertFalse(configuration.isClusterPermission("indices:monitor/settings/get"));
    }

    @Test
    public void indexSettingsDescribeIsGrantedByClusterCompositeOpsRo() throws Exception {
        // A cluster permission is only reachable through a cluster-type action group. cluster_composite_ops_ro is the group
        // for read-only indices:* actions that are evaluated as cluster permissions (mget, msearch, scroll, ...), so the index
        // settings describe action is listed there rather than under cluster_monitor.
        JsonNode groups = DefaultObjectMapper.yamlMapper()
            .readTree(ActionConfigurationTest.class.getResourceAsStream("/static_config/static_action_groups.yml"));
        JsonNode compositeOpsRo = groups.get("cluster_composite_ops_ro");
        assertEquals("cluster", compositeOpsRo.get("type").asText());
        List<String> allowed = new ArrayList<>();
        compositeOpsRo.get("allowed_actions").forEach(action -> allowed.add(action.asText()));
        assertThat(allowed, hasItem(DESCRIBE_INDEX_SETTINGS));
    }
}
