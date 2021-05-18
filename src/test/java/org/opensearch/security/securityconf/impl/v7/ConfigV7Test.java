package org.opensearch.security.securityconf.impl.v7;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.DefaultObjectMapper;

import com.google.common.collect.ImmutableList;

@RunWith(Parameterized.class)
public class ConfigV7Test {
    private final boolean omitDefaults;

    @Parameterized.Parameters
    public static Iterable<Boolean> omitDefaults() {
        return ImmutableList.of(Boolean.FALSE, Boolean.TRUE);
    }

    public void assertEquals(ConfigV7.Kibana expected, JsonNode node) {
        if (omitDefaults && !expected.multitenancy_enabled) {
            // false (default) is not persisted
            Assert.assertNull(node.get("multitenancy_enabled"));
        } else {
            Assert.assertEquals(expected.multitenancy_enabled, node.get("multitenancy_enabled").asBoolean());
        }
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
    }

    private void assertEquals(ConfigV7.Kibana expected, ConfigV7.Kibana actual) {
        if (omitDefaults && !expected.multitenancy_enabled) {
            // BUG: false is omitted and is restored to default (which is true) instead of false
            Assert.assertTrue(actual.multitenancy_enabled);
        } else {
            Assert.assertEquals(expected.multitenancy_enabled, actual.multitenancy_enabled);
        }
        if (expected.server_username == null) {
            // null is restored to default instead of null
            Assert.assertEquals(new ConfigV7.Kibana().server_username, actual.server_username);
        } else {
            Assert.assertEquals(expected.server_username, actual.server_username);
        }
        // null is restored to default (which is null).
        Assert.assertEquals(expected.opendistro_role, actual.opendistro_role);
        if (expected.index == null) {
            // null is restored to default instead of null
            Assert.assertEquals(new ConfigV7.Kibana().index, actual.index);
        } else {
            Assert.assertEquals(expected.index, actual.index);
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
