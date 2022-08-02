/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.sanity.tests;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.hamcrest.MatcherAssert;
import org.junit.Test;

import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;


@SuppressWarnings("unchecked")
public class SingleClusterSanityIT extends SecurityRestTestCase {

    private static final String SECURITY_PLUGIN_NAME = "opensearch-security";

    @Test
    public void testSecurityPluginInstallation() throws Exception {
        verifyPluginInstallationOnAllNodes();
    }

    private void verifyPluginInstallationOnAllNodes() throws Exception {

        Map<String, Map<String, Object>> nodesInCluster = (Map<String, Map<String, Object>>) getAsMapByAdmin("_nodes").get("nodes");

        for (Map<String, Object> node : nodesInCluster.values()) {

            List<Map<String, Object>> plugins = (List<Map<String, Object>>) node.get("plugins");
            Set<Object> pluginNames = plugins.stream().map(map -> map.get("name")).collect(Collectors.toSet());

            MatcherAssert.assertThat(pluginNames, contains(SECURITY_PLUGIN_NAME));
        }
        MatcherAssert.assertThat(nodesInCluster, is(not(anEmptyMap())));
    }
}
