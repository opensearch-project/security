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
        Assert.assertEquals(expected.multitenancy_enabled, node.get("multitenancy_enabled").asBoolean());
        assertThat(node.get("sign_in_options").isArray(), is(true));
        assertThat(node.get("sign_in_options").toString(), containsString(expected.sign_in_options.get(0).toString()));

        if (expected.server_username == null) {
            Assert.assertNull(node.get("server_username"));
        } else {
            Assert.assertEquals(expected.server_username, node.get("server_username").asText());
        }
        if (expected.index == null) {
            // null is not persisted
            Assert.assertNull(node.get("index"));
        } else {
            Assert.assertEquals(expected.index, node.get("index").asText());
        }
        if (expected.opendistro_role == null) {
            Assert.assertNull(node.get("opendistro_role"));
        } else {
            Assert.assertEquals(expected.opendistro_role, node.get("opendistro_role").asText());
        }
        if (omitDefaults && !expected.do_not_fail_on_forbidden) {
            // false (default) is not persisted
            Assert.assertNull(node.get("do_not_fail_on_forbidden"));
        } else {
            Assert.assertEquals(expected.do_not_fail_on_forbidden, node.get("do_not_fail_on_forbidden").asBoolean());
        }
    }

    private void assertEquals(ConfigV6.Kibana expected, ConfigV6.Kibana actual) {
        Assert.assertEquals(expected.multitenancy_enabled, actual.multitenancy_enabled);
        assertThat(expected.sign_in_options, is(actual.sign_in_options));
        if (expected.server_username == null) {
            // null is restored to default instead of null
            Assert.assertEquals(new ConfigV6.Kibana().server_username, actual.server_username);
        } else {
            Assert.assertEquals(expected.server_username, actual.server_username);
        }
        // null is restored to default (which is null).
        Assert.assertEquals(expected.opendistro_role, actual.opendistro_role);
        if (expected.index == null) {
            // null is restored to default instead of null
            Assert.assertEquals(new ConfigV6.Kibana().index, actual.index);
        } else {
            Assert.assertEquals(expected.index, actual.index);
        }
        Assert.assertEquals(expected.do_not_fail_on_forbidden, actual.do_not_fail_on_forbidden);
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
        assertEquals(kibana, DefaultObjectMapper.readTree(json));
        assertEquals(kibana, DefaultObjectMapper.readValue(json, ConfigV6.Kibana.class));

        kibana.multitenancy_enabled = false;
        kibana.server_username = null;
        kibana.opendistro_role = null;
        kibana.index = null;
        kibana.do_not_fail_on_forbidden = false;
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));
        assertEquals(kibana, DefaultObjectMapper.readValue(json, ConfigV6.Kibana.class));

        kibana.multitenancy_enabled = true;
        kibana.server_username = "user";
        kibana.opendistro_role = "role";
        kibana.index = "index";
        kibana.do_not_fail_on_forbidden = true;
        json = DefaultObjectMapper.writeValueAsString(kibana, omitDefaults);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));
        assertEquals(kibana, DefaultObjectMapper.readValue(json, ConfigV6.Kibana.class));
    }

    @Test
    public void testOnBehalfOfSettings() {
        ConfigV6.OnBehalfOfSettings oboSettings;

        oboSettings = new ConfigV6.OnBehalfOfSettings();
        Assert.assertEquals(oboSettings.getOboEnabled(), Boolean.FALSE);
        Assert.assertNull(oboSettings.getSigningKey());
        Assert.assertNull(oboSettings.getEncryptionKey());
    }
}
