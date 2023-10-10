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

import org.opensearch.security.DefaultObjectMapper;

import static org.hamcrest.MatcherAssert.assertThat;

import static org.hamcrest.CoreMatchers.is;

@RunWith(Parameterized.class)
public class ConfigV7Test {
    private final boolean omitDefaults;

    @Parameterized.Parameters
    public static Iterable<Boolean> omitDefaults() {
        return ImmutableList.of(Boolean.FALSE, Boolean.TRUE);
    }

    public void assertKibanaProperties(ConfigV7.Kibana expected, JsonNode node) {
        assertThat(node.get("multitenancy_enabled").asBoolean(), is(expected.multitenancy_enabled));

        if (expected.server_username == null) {
            assertThat(node.has("server_username"), is(false));
        } else {
            assertThat(node.get("server_username").asText(), is(expected.server_username));
        }

        if (expected.index == null) {
            assertThat(node.has("index"), is(false));
        } else {
            assertThat(node.get("index").asText(), is(expected.index));
        }

        if (expected.opendistro_role == null) {
            assertThat(node.has("opendistro_role"), is(false));
        } else {
            assertThat(node.get("opendistro_role").asText(), is(expected.opendistro_role));
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
        assertKibanaProperties(kibana, DefaultObjectMapper.readTree(json));

        kibana.multitenancy_enabled = false;
        kibana.server_username = null;
        kibana.opendistro_role = null;
        kibana.index = null;
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertKibanaProperties(kibana, DefaultObjectMapper.readTree(json));

        kibana.multitenancy_enabled = true;
        kibana.server_username = "user";
        kibana.opendistro_role = "role";
        kibana.index = "index";
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertKibanaProperties(kibana, DefaultObjectMapper.readTree(json));

    }
}
