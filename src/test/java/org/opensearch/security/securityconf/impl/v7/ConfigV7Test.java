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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

import org.opensearch.security.DefaultObjectMapper;

@RunWith(Parameterized.class)
public class ConfigV7Test {
    private final boolean omitDefaults;

    @Parameterized.Parameters
    public static Iterable<Boolean> omitDefaults() {
        return ImmutableList.of(Boolean.FALSE, Boolean.TRUE);
    }

    public void assertEquals(ConfigV7.Kibana expected, JsonNode node) {
        // Replaced if else statements with inline operator for optimization
        assertThat(node.get("multitenancy_enabled").asBoolean(), is(expected.multitenancy_enabled));
        assertThat(node.get("server_username").asText(), is(expected.server_username == null ? nullValue() : expected.server_username));
        // null is not persisted if expected.index is null
        assertThat(node.get("index").asText(), is(expected.index == null ? nullValue() : expected.index));
        assertThat(node.get("opendistro_role").asText(), is(expected.opendistro_role == null ? nullValue() : expected.opendistro_role));
    }

    private void assertEquals(ConfigV7.Kibana expected, ConfigV7.Kibana actual) {
        // Replaced if else statements with inline operator for optimization
        assertThat(actual.multitenancy_enabled, is(expected.multitenancy_enabled));
        // if expected.server_username is null, then null is restored to default instead of null
        assertThat(
            actual.server_username,
            is(expected.server_username == null ? equalTo(new ConfigV7.Kibana().server_username) : expected.server_username)
        );
        // null is restored to default (which is null).
        assertThat(actual.opendistro_role, is(equalTo(expected.opendistro_role)));
        // if expected.index is null, null is restored to default instead of null
        assertThat(actual.index, is(expected.index == null ? equalTo(new ConfigV7.Kibana().index) : expected.index));
    }

    public ConfigV7Test(boolean omitDefaults) {
        this.omitDefaults = omitDefaults;
    }

    // assertEquals() is still used but the internal assertions now use assertThat() for handling null checks
    @Test
    public void testDashboards() throws Exception {
        ConfigV7.Kibana kibana;
        String json;

        kibana = new ConfigV7.Kibana();
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));
        assertEquals(kibana, DefaultObjectMapper.readValue(json, ConfigV7.Kibana.class));

        kibana.multitenancy_enabled = false;
        kibana.server_username = null;
        kibana.opendistro_role = null;
        kibana.index = null;
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));
        assertEquals(kibana, DefaultObjectMapper.readValue(json, ConfigV7.Kibana.class));

        kibana.multitenancy_enabled = true;
        kibana.server_username = "user";
        kibana.opendistro_role = "role";
        kibana.index = "index";
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));
        assertEquals(kibana, DefaultObjectMapper.readValue(json, ConfigV7.Kibana.class));
    }
}
