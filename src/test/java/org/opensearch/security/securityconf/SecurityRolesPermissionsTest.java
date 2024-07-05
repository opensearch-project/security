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

package org.opensearch.security.securityconf;

import java.io.IOException;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.PermissionBuilder;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import org.mockito.Mockito;

import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.CERTS_INFO_ACTION;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.ENDPOINTS_WITH_PERMISSIONS;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.RELOAD_CERTS_ACTION;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.SECURITY_CONFIG_UPDATE;

public class SecurityRolesPermissionsTest {

    static final Map<String, ObjectNode> NO_REST_ADMIN_PERMISSIONS_ROLES = ImmutableMap.<String, ObjectNode>builder()
        .put("all_access", role("*"))
        .put("all_cluster_and_indices", role("custer:*", "indices:*"))
        .build();

    static final Map<String, ObjectNode> REST_ADMIN_PERMISSIONS_FULL_ACCESS_ROLES = ImmutableMap.<String, ObjectNode>builder()
        .put("security_rest_api_full_access", role(allRestApiPermissions()))
        .put("security_rest_api_full_access_with_star", role("restapi:admin/*"))
        .build();

    static String restAdminApiRoleName(final String endpoint) {
        return String.format("security_rest_api_%s_only", endpoint);
    }

    static final Map<String, ObjectNode> REST_ADMIN_PERMISSIONS_ROLES = ENDPOINTS_WITH_PERMISSIONS.entrySet().stream().flatMap(e -> {
        final String endpoint = e.getKey().name().toLowerCase(Locale.ROOT);
        final PermissionBuilder pb = e.getValue();
        if (e.getKey() == Endpoint.SSL) {
            return Stream.of(
                new SimpleEntry<>(restAdminApiRoleName(CERTS_INFO_ACTION), role(pb.build(CERTS_INFO_ACTION))),
                new SimpleEntry<>(restAdminApiRoleName(RELOAD_CERTS_ACTION), role(pb.build(RELOAD_CERTS_ACTION)))
            );
        } else if (e.getKey() == Endpoint.CONFIG) {
            return Stream.of(new SimpleEntry<>(restAdminApiRoleName(SECURITY_CONFIG_UPDATE), role(pb.build(SECURITY_CONFIG_UPDATE))));
        } else {
            return Stream.of(new SimpleEntry<>(restAdminApiRoleName(endpoint), role(pb.build())));
        }
    }).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

    static ObjectNode role(final String... clusterPermissions) {
        final ArrayNode clusterPermissionsArrayNode = DefaultObjectMapper.objectMapper.createArrayNode();
        Arrays.stream(clusterPermissions).forEach(clusterPermissionsArrayNode::add);
        return DefaultObjectMapper.objectMapper.createObjectNode()
            .put("reserved", true)
            .set("cluster_permissions", clusterPermissionsArrayNode);
    }

    static String[] allRestApiPermissions() {
        return ENDPOINTS_WITH_PERMISSIONS.entrySet().stream().flatMap(entry -> {
            if (entry.getKey() == Endpoint.SSL) {
                return Stream.of(entry.getValue().build(CERTS_INFO_ACTION), entry.getValue().build(RELOAD_CERTS_ACTION));
            } else if (entry.getKey() == Endpoint.CONFIG) {
                return Stream.of(entry.getValue().build(SECURITY_CONFIG_UPDATE));
            } else {
                return Stream.of(entry.getValue().build());
            }
        }).toArray(String[]::new);
    }

    final ConfigModel configModel;

    public SecurityRolesPermissionsTest() throws IOException {
        this.configModel = new ConfigModelV7(
            createRolesConfig(),
            createRoleMappingsConfig(),
            createActionGroupsConfig(),
            createTenantsConfig(),
            Mockito.mock(DynamicConfigModel.class),
            Settings.EMPTY
        );
    }

    @Test
    public void hasNoExplicitClusterPermissionPermissionForRestAdmin() {
        for (final String role : NO_REST_ADMIN_PERMISSIONS_ROLES.keySet()) {
            final SecurityRoles securityRolesForRole = configModel.getSecurityRoles().filter(ImmutableSet.of(role));
            for (final Map.Entry<Endpoint, PermissionBuilder> entry : ENDPOINTS_WITH_PERMISSIONS.entrySet()) {
                final Endpoint endpoint = entry.getKey();
                final PermissionBuilder permissionBuilder = entry.getValue();
                if (endpoint == Endpoint.SSL) {
                    Assert.assertFalse(
                        endpoint.name(),
                        securityRolesForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build(CERTS_INFO_ACTION))
                    );
                    Assert.assertFalse(
                        endpoint.name(),
                        securityRolesForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build(RELOAD_CERTS_ACTION))
                    );
                } else if (endpoint == Endpoint.CONFIG) {
                    Assert.assertFalse(
                        endpoint.name(),
                        securityRolesForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build(SECURITY_CONFIG_UPDATE))
                    );
                } else {
                    Assert.assertFalse(
                        endpoint.name(),
                        securityRolesForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build())
                    );
                }
            }
        }
    }

    @Test
    public void hasExplicitClusterPermissionPermissionForRestAdminWitFullAccess() {
        for (final String role : REST_ADMIN_PERMISSIONS_FULL_ACCESS_ROLES.keySet()) {
            final SecurityRoles securityRolesForRole = configModel.getSecurityRoles().filter(ImmutableSet.of(role));
            for (final Map.Entry<Endpoint, PermissionBuilder> entry : ENDPOINTS_WITH_PERMISSIONS.entrySet()) {
                final Endpoint endpoint = entry.getKey();
                final PermissionBuilder permissionBuilder = entry.getValue();
                if (endpoint == Endpoint.SSL) {
                    Assert.assertTrue(
                        endpoint.name() + "/" + CERTS_INFO_ACTION,
                        securityRolesForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build(CERTS_INFO_ACTION))
                    );
                    Assert.assertTrue(
                        endpoint.name() + "/" + CERTS_INFO_ACTION,
                        securityRolesForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build(RELOAD_CERTS_ACTION))
                    );
                } else if (endpoint == Endpoint.CONFIG) {
                    Assert.assertTrue(
                        endpoint.name() + "/" + SECURITY_CONFIG_UPDATE,
                        securityRolesForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build(SECURITY_CONFIG_UPDATE))
                    );
                } else {
                    Assert.assertTrue(
                        endpoint.name(),
                        securityRolesForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build())
                    );
                }
            }
        }
    }

    @Test
    public void hasExplicitClusterPermissionPermissionForRestAdmin() {
        // verify all endpoint except SSL and verify CONFIG endpoints
        final Collection<Endpoint> noSslEndpoints = ENDPOINTS_WITH_PERMISSIONS.keySet()
            .stream()
            .filter(e -> e != Endpoint.SSL && e != Endpoint.CONFIG)
            .collect(Collectors.toList());
        for (final Endpoint endpoint : noSslEndpoints) {
            final String permission = ENDPOINTS_WITH_PERMISSIONS.get(endpoint).build();
            final SecurityRoles allowOnePermissionRole = configModel.getSecurityRoles()
                .filter(ImmutableSet.of(restAdminApiRoleName(endpoint.name().toLowerCase(Locale.ROOT))));
            Assert.assertTrue(endpoint.name(), allowOnePermissionRole.hasExplicitClusterPermissionPermission(permission));
            assertHasNoPermissionsForRestApiAdminOnePermissionRole(endpoint, allowOnePermissionRole);
        }
        // verify SSL endpoint with 2 actions
        for (final String sslAction : ImmutableSet.of(CERTS_INFO_ACTION, RELOAD_CERTS_ACTION)) {
            final SecurityRoles sslAllowRole = configModel.getSecurityRoles().filter(ImmutableSet.of(restAdminApiRoleName(sslAction)));
            final PermissionBuilder permissionBuilder = ENDPOINTS_WITH_PERMISSIONS.get(Endpoint.SSL);
            Assert.assertTrue(
                Endpoint.SSL + "/" + sslAction,
                sslAllowRole.hasExplicitClusterPermissionPermission(permissionBuilder.build(sslAction))
            );
            assertHasNoPermissionsForRestApiAdminOnePermissionRole(Endpoint.SSL, sslAllowRole);
        }
        // verify CONFIG endpoint with 1 action
        final SecurityRoles securityConfigAllowRole = configModel.getSecurityRoles()
            .filter(ImmutableSet.of(restAdminApiRoleName(SECURITY_CONFIG_UPDATE)));
        final PermissionBuilder permissionBuilder = ENDPOINTS_WITH_PERMISSIONS.get(Endpoint.CONFIG);
        Assert.assertTrue(
            Endpoint.SSL + "/" + SECURITY_CONFIG_UPDATE,
            securityConfigAllowRole.hasExplicitClusterPermissionPermission(permissionBuilder.build(SECURITY_CONFIG_UPDATE))
        );
        assertHasNoPermissionsForRestApiAdminOnePermissionRole(Endpoint.CONFIG, securityConfigAllowRole);
    }

    void assertHasNoPermissionsForRestApiAdminOnePermissionRole(final Endpoint allowEndpoint, final SecurityRoles allowOnlyRoleForRole) {
        final Collection<Endpoint> noPermissionEndpoints = ENDPOINTS_WITH_PERMISSIONS.keySet()
            .stream()
            .filter(e -> e != allowEndpoint)
            .collect(Collectors.toList());
        for (final Endpoint endpoint : noPermissionEndpoints) {
            final PermissionBuilder permissionBuilder = ENDPOINTS_WITH_PERMISSIONS.get(endpoint);
            if (endpoint == Endpoint.SSL) {
                Assert.assertFalse(
                    endpoint.name(),
                    allowOnlyRoleForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build(CERTS_INFO_ACTION))
                );
                Assert.assertFalse(
                    endpoint.name(),
                    allowOnlyRoleForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build(RELOAD_CERTS_ACTION))
                );
            } else {
                Assert.assertFalse(endpoint.name(), allowOnlyRoleForRole.hasExplicitClusterPermissionPermission(permissionBuilder.build()));
            }
        }
    }

    static ObjectNode meta(final String type) {
        return DefaultObjectMapper.objectMapper.createObjectNode().put("type", type).put("config_version", 2);
    }

    static <T> SecurityDynamicConfiguration<T> createRolesConfig() throws IOException {
        final ObjectNode rolesNode = DefaultObjectMapper.objectMapper.createObjectNode();
        rolesNode.set("_meta", meta("roles"));
        NO_REST_ADMIN_PERMISSIONS_ROLES.forEach(rolesNode::set);
        REST_ADMIN_PERMISSIONS_FULL_ACCESS_ROLES.forEach(rolesNode::set);
        REST_ADMIN_PERMISSIONS_ROLES.forEach(rolesNode::set);
        return SecurityDynamicConfiguration.fromNode(rolesNode, CType.ROLES, 2, 0, 0);
    }

    static <T> SecurityDynamicConfiguration<T> createRoleMappingsConfig() throws IOException {
        final ObjectNode metaNode = DefaultObjectMapper.objectMapper.createObjectNode();
        metaNode.set("_meta", meta("rolesmapping"));
        return SecurityDynamicConfiguration.fromNode(metaNode, CType.ROLESMAPPING, 2, 0, 0);
    }

    static <T> SecurityDynamicConfiguration<T> createActionGroupsConfig() throws IOException {
        final ObjectNode metaNode = DefaultObjectMapper.objectMapper.createObjectNode();
        metaNode.set("_meta", meta("actiongroups"));
        return SecurityDynamicConfiguration.fromNode(metaNode, CType.ACTIONGROUPS, 2, 0, 0);
    }

    static <T> SecurityDynamicConfiguration<T> createTenantsConfig() throws IOException {
        final ObjectNode metaNode = DefaultObjectMapper.objectMapper.createObjectNode();
        metaNode.set("_meta", meta("tenants"));
        return SecurityDynamicConfiguration.fromNode(metaNode, CType.TENANTS, 2, 0, 0);
    }

}
