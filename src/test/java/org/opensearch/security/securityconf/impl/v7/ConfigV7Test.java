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

package org.opensearch.security.securityconf.impl.v7;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import static org.assertj.core.api.Assertions.assertThat;
import org.opensearch.security.DefaultObjectMapper;

@RunWith(Parameterized.class)
public class ConfigV7Test {
    private final boolean omitDefaults;

    @Parameterized.Parameters
    public static Iterable<Boolean> omitDefaults() {
        return ImmutableList.of(Boolean.FALSE, Boolean.TRUE);
    }

    public void assertEquals(ConfigV7.Kibana expected, JsonNode node) {
        assertThat(node.get("multitenancy_enabled").asBoolean()).as("Multitenancy Enabled").isEqualTo(expected.multitenancy_enabled);

        if (expected.server_username == null) {
            assertThat(node.get("server_username")).isNull();
        } else {
            assertThat(node.get("server_username").asText()).as("Server Username").isEqualTo(expected.server_username);
        }

        if (expected.index == null) {
            assertThat(node.get("index")).isNull();
        } else {
            assertThat(node.get("index").asText()).as("Index").isEqualTo(expected.index);
        }

        if (expected.opendistro_role == null) {
            assertThat(node.get("opendistro_role")).isNull();
        } else {
            assertThat(node.get("opendistro_role").asText()).as("OpenDistro Role").isEqualTo(expected.opendistro_role);
        }
    }

    public ConfigV7Test(boolean omitDefaults) {
        this.omitDefaults = omitDefaults;
    }

    @Test
    public void testDashboards() throws Exception {
        ConfigV7.Kibana kibana;
        String json;

        kibana = new ConfigV7.Kibana();
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));

        kibana.multitenancy_enabled = false;
        kibana.server_username = null;
        kibana.opendistro_role = null;
        kibana.index = null;
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));

        kibana.multitenancy_enabled = true;
        kibana.server_username = "user";
        kibana.opendistro_role = "role";
        kibana.index = "index";
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));

    }
}
