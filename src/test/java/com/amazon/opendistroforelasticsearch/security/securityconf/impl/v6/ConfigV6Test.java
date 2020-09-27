package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;

import org.elasticsearch.common.Strings;

public class ConfigV6Test {
    public static void assertEquals(ConfigV6.Kibana expected, JsonNode node) {
        Assert.assertEquals(expected.multitenancy_enabled, node.get("multitenancy_enabled").asBoolean());
        Assert.assertEquals(expected.server_username, node.get("server_username").asText());
        Assert.assertEquals(expected.index, node.get("index").asText());
        if (Strings.isNullOrEmpty(expected.opendistro_role)) {
            Assert.assertNull(node.get("opendistro_role"));
        } else {
            Assert.assertEquals(expected.opendistro_role, node.get("opendistro_role").asText());
        }
        Assert.assertEquals(expected.do_not_fail_on_forbidden, node.get("do_not_fail_on_forbidden").asBoolean());
    }

    private static void assertEquals(ConfigV6.Kibana expected, ConfigV6.Kibana actual) {
        Assert.assertEquals(expected.multitenancy_enabled, actual.multitenancy_enabled);
        Assert.assertEquals(expected.server_username, actual.server_username);
        Assert.assertEquals(expected.opendistro_role, actual.opendistro_role);
        Assert.assertEquals(expected.index, actual.index);
        Assert.assertEquals(expected.do_not_fail_on_forbidden, actual.do_not_fail_on_forbidden);
    }

    @Test
    public void testKibana() throws Exception {
        ConfigV6.Kibana kibana;
        String json;

        kibana = new ConfigV6.Kibana();
        json = DefaultObjectMapper.writeValueAsString(kibana, false);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));
        assertEquals(kibana, DefaultObjectMapper.readValue(json, ConfigV6.Kibana.class));

        json = DefaultObjectMapper.writeValueAsString(kibana, true);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));
        assertEquals(kibana, DefaultObjectMapper.readValue(json, ConfigV6.Kibana.class));

        kibana.multitenancy_enabled = false;
        kibana.server_username = "user";
        kibana.opendistro_role = "role";
        kibana.index = "index";
        kibana.do_not_fail_on_forbidden = true;

        json = DefaultObjectMapper.writeValueAsString(kibana, false);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));
        assertEquals(kibana, DefaultObjectMapper.readValue(json, ConfigV6.Kibana.class));

        json = DefaultObjectMapper.writeValueAsString(kibana, true);
        assertEquals(kibana, DefaultObjectMapper.readTree(json));
        assertEquals(kibana, DefaultObjectMapper.readValue(json, ConfigV6.Kibana.class));

    }

}
