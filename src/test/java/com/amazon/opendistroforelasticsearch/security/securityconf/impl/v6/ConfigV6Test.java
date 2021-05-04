package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;

import com.google.common.collect.ImmutableList;

@RunWith(Parameterized.class)
public class ConfigV6Test {
    private final boolean omitDefaults;

    @Parameterized.Parameters
    public static Iterable<Boolean> omitDefaults() {
        return ImmutableList.of(Boolean.FALSE, Boolean.TRUE);
    }

    public void assertEquals(ConfigV6.OpenSearchDashboards expected, JsonNode node) {
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
        if (omitDefaults && !expected.do_not_fail_on_forbidden) {
            // false (default) is not persisted
            Assert.assertNull(node.get("do_not_fail_on_forbidden"));
        } else {
            Assert.assertEquals(expected.do_not_fail_on_forbidden, node.get("do_not_fail_on_forbidden").asBoolean());
        }
    }

    private void assertEquals(ConfigV6.OpenSearchDashboards expected, ConfigV6.OpenSearchDashboards actual) {
        if (omitDefaults && !expected.multitenancy_enabled) {
            // BUG: false is omitted and is restored to default (which is true) instead of false
            Assert.assertTrue(actual.multitenancy_enabled);
        } else {
            Assert.assertEquals(expected.multitenancy_enabled, actual.multitenancy_enabled);
        }
        if (expected.server_username == null) {
            // null is restored to default instead of null
            Assert.assertEquals(new ConfigV6.OpenSearchDashboards().server_username, actual.server_username);
        } else {
            Assert.assertEquals(expected.server_username, actual.server_username);
        }
        // null is restored to default (which is null).
        Assert.assertEquals(expected.opendistro_role, actual.opendistro_role);
        if (expected.index == null) {
            // null is restored to default instead of null
            Assert.assertEquals(new ConfigV6.OpenSearchDashboards().index, actual.index);
        } else {
            Assert.assertEquals(expected.index, actual.index);
        }
        Assert.assertEquals(expected.do_not_fail_on_forbidden, actual.do_not_fail_on_forbidden);
    }

    public ConfigV6Test(boolean omitDefaults) {
        this.omitDefaults = omitDefaults;
    }

    @Test
    public void testOpenSearchDashboards() throws Exception {
        ConfigV6.OpenSearchDashboards openSearchDashboards;
        String json;

        openSearchDashboards = new ConfigV6.OpenSearchDashboards();
        json = DefaultObjectMapper.writeValueAsString(openSearchDashboards, omitDefaults);
        assertEquals(openSearchDashboards, DefaultObjectMapper.readTree(json));
        assertEquals(openSearchDashboards, DefaultObjectMapper.readValue(json, ConfigV6.OpenSearchDashboards.class));

        openSearchDashboards.multitenancy_enabled = false;
        openSearchDashboards.server_username = null;
        openSearchDashboards.opendistro_role = null;
        openSearchDashboards.index = null;
        openSearchDashboards.do_not_fail_on_forbidden = false;
        json = DefaultObjectMapper.writeValueAsString(openSearchDashboards, omitDefaults);
        assertEquals(openSearchDashboards, DefaultObjectMapper.readTree(json));
        assertEquals(openSearchDashboards, DefaultObjectMapper.readValue(json, ConfigV6.OpenSearchDashboards.class));

        openSearchDashboards.multitenancy_enabled = true;
        openSearchDashboards.server_username = "user";
        openSearchDashboards.opendistro_role = "role";
        openSearchDashboards.index = "index";
        openSearchDashboards.do_not_fail_on_forbidden = true;
        json = DefaultObjectMapper.writeValueAsString(openSearchDashboards, omitDefaults);
        assertEquals(openSearchDashboards, DefaultObjectMapper.readTree(json));
        assertEquals(openSearchDashboards, DefaultObjectMapper.readValue(json, ConfigV6.OpenSearchDashboards.class));
    }
}
