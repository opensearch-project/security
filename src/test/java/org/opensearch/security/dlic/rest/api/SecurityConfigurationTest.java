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

package org.opensearch.security.dlic.rest.api;

import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class SecurityConfigurationTest {

    SecurityDynamicConfiguration<?> configuration;

    private final ObjectMapper objectMapper = DefaultObjectMapper.objectMapper;

    @Before
    public void setConfiguration() throws Exception {
        final var config = objectMapper.createObjectNode();
        config.set("_meta", objectMapper.createObjectNode().put("type", CType.ROLES.toLCString()).put("config_version", 2));
        config.set("kibana_read_only", objectMapper.createObjectNode().put("reserved", true));
        config.set("security_rest_api_access", objectMapper.createObjectNode().put("reserved", true));
        configuration = SecurityDynamicConfiguration.fromJson(objectMapper.writeValueAsString(config), CType.ROLES, 2, 1, 1);
    }

    @Test
    public void failsIfConfigurationNull() {
        assertThrows(NullPointerException.class, () -> SecurityConfiguration.of("some_entity", null));
    }

    @Test
    public void failsIfConfigurationOrRequestContentNull() {
        assertThrows(NullPointerException.class, () -> SecurityConfiguration.of(objectMapper.createObjectNode(), "some_entity", null));
        assertThrows(NullPointerException.class, () -> SecurityConfiguration.of(null, "some_entity", configuration));
    }

    @Test
    public void testNewOrUpdatedEntity() {
        var securityConfiguration = SecurityConfiguration.of("security_rest_api_access", configuration);
        assertTrue(securityConfiguration.entityExists());
        assertEquals("security_rest_api_access", securityConfiguration.entityName());

        securityConfiguration = SecurityConfiguration.of("security_rest_api_access_v2", configuration);
        assertFalse(securityConfiguration.entityExists());
        assertEquals("security_rest_api_access_v2", securityConfiguration.entityName());

        final var newRole = new RoleV7();
        newRole.setCluster_permissions(List.of("cluster:admin/opendistro/alerting/alerts/get"));
        configuration.putCObject("security_rest_api_access_v2", newRole);
        assertTrue(configuration.exists("security_rest_api_access_v2"));
        assertFalse(securityConfiguration.entityExists());
        assertEquals("security_rest_api_access_v2", securityConfiguration.entityName());
    }

    @Test
    public void testNoEntityNameConfiguration() {
        final var securityConfiguration = SecurityConfiguration.of(null, configuration);
        assertFalse(securityConfiguration.entityExists());
        assertEquals("empty", securityConfiguration.entityName());
    }

}
