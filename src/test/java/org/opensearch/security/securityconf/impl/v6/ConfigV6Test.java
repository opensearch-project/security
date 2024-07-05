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

package org.opensearch.security.securityconf.impl.v6;

import com.google.common.collect.ImmutableList;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.DefaultObjectMapper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

@RunWith(Parameterized.class)
public class ConfigV6Test {
    private final boolean omitDefaults;

    @Parameterized.Parameters
    public static Iterable<Boolean> omitDefaults() {
        return ImmutableList.of(Boolean.FALSE, Boolean.TRUE);
    }

    public void assertEquals(ConfigV6.Kibana expected, JsonNode node) {
        assertThat(node.get("multitenancy_enabled").asBoolean(), is(expected.multitenancy_enabled));
        assertThat(node.get("sign_in_options").isArray(), is(true));
        assertThat(node.get("sign_in_options").toString(), containsString(expected.sign_in_options.get(0).toString()));

        if (expected.server_username == null) {
            Assert.assertNull(node.get("server_username"));
        } else {
            assertThat(node.get("server_username").asText(), is(expected.server_username));
        }
        if (expected.index == null) {
            // null is not persisted
            Assert.assertNull(node.get("index"));
        } else {
            assertThat(node.get("index").asText(), is(expected.index));
        }
        if (expected.opendistro_role == null) {
            Assert.assertNull(node.get("opendistro_role"));
        } else {
            assertThat(node.get("opendistro_role").asText(), is(expected.opendistro_role));
        }
        if (omitDefaults && !expected.do_not_fail_on_forbidden) {
            // false (default) is not persisted
            Assert.assertNull(node.get("do_not_fail_on_forbidden"));
        } else {
            assertThat(node.get("do_not_fail_on_forbidden").asBoolean(), is(expected.do_not_fail_on_forbidden));
        }
    }

    private void assertEquals(ConfigV6.Kibana expected, ConfigV6.Kibana actual) {
        assertThat(actual.multitenancy_enabled, is(expected.multitenancy_enabled));
        assertThat(expected.sign_in_options, is(actual.sign_in_options));
        if (expected.server_username == null) {
            // null is restored to default instead of null
            assertThat(actual.server_username, is(new ConfigV6.Kibana().server_username));
        } else {
            assertThat(actual.server_username, is(expected.server_username));
        }
        // null is restored to default (which is null).
        assertThat(actual.opendistro_role, is(expected.opendistro_role));
        if (expected.index == null) {
            // null is restored to default instead of null
            assertThat(actual.index, is(new ConfigV6.Kibana().index));
        } else {
            assertThat(actual.index, is(expected.index));
        }
        assertThat(actual.do_not_fail_on_forbidden, is(expected.do_not_fail_on_forbidden));
    }

    public ConfigV6Test(boolean omitDefaults) {
        this.omitDefaults = omitDefaults;
    }

    @Test
    public void testDashboards() throws Exception {
        ConfigV6.Kibana kibana;
        String json;

        kibana = new ConfigV6.Kibana();
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertThat(DefaultObjectMapper.readTree(json), is(kibana));
        assertThat(DefaultObjectMapper.readValue(json, ConfigV6.Kibana.class), is(kibana));

        kibana.multitenancy_enabled = false;
        kibana.server_username = null;
        kibana.opendistro_role = null;
        kibana.index = null;
        kibana.do_not_fail_on_forbidden = false;
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertThat(DefaultObjectMapper.readTree(json), is(kibana));
        assertThat(DefaultObjectMapper.readValue(json, ConfigV6.Kibana.class), is(kibana));

        kibana.multitenancy_enabled = true;
        kibana.server_username = "user";
        kibana.opendistro_role = "role";
        kibana.index = "index";
        kibana.do_not_fail_on_forbidden = true;
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertThat(DefaultObjectMapper.readTree(json), is(kibana));
        assertThat(DefaultObjectMapper.readValue(json, ConfigV6.Kibana.class), is(kibana));
    }

    @Test
    public void testOnBehalfOfSettings() {
        ConfigV6.OnBehalfOfSettings oboSettings;

        oboSettings = new ConfigV6.OnBehalfOfSettings();
        assertThat(Boolean.FALSE, is(oboSettings.getOboEnabled()));
        Assert.assertNull(oboSettings.getSigningKey());
        Assert.assertNull(oboSettings.getEncryptionKey());
    }
}
