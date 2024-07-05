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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;

import org.mockito.quality.Strictness;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

public class SecurityRolesPermissionsV6Test {
    static final String TEST_INDEX = ".test";

    // a role with * permission but no system:admin/system_index permission
    static final Map<String, ObjectNode> NO_EXPLICIT_SYSTEM_INDEX_PERMISSION = ImmutableMap.<String, ObjectNode>builder()
        .put("all_access_without_system_index_permission", role(new String[] { "*" }, new String[] { TEST_INDEX }, new String[] { "*" }))
        .build();

    static final Map<String, ObjectNode> HAS_SYSTEM_INDEX_PERMISSION = ImmutableMap.<String, ObjectNode>builder()
        .put(
            "has_system_index_permission",
            role(new String[] { "*" }, new String[] { TEST_INDEX }, new String[] { ConfigConstants.SYSTEM_INDEX_PERMISSION })
        )
        .build();

    static ObjectNode role(final String[] clusterPermissions, final String[] indexPatterns, final String[] allowedActions) {
        ObjectMapper objectMapper = DefaultObjectMapper.objectMapper;
        // form cluster permissions
        final ArrayNode clusterPermissionsArrayNode = objectMapper.createArrayNode();
        Arrays.stream(clusterPermissions).forEach(clusterPermissionsArrayNode::add);

        // form index_permissions
        ArrayNode permissions = objectMapper.createArrayNode();
        Arrays.stream(allowedActions).forEach(permissions::add); // permission in v6 format

        ObjectNode permissionNode = objectMapper.createObjectNode();
        permissionNode.set("*", permissions); // type : "*"

        ObjectNode indexPermission = objectMapper.createObjectNode();
        indexPermission.set("*", permissionNode); // '*' -> all indices

        // add both to the role
        ObjectNode role = objectMapper.createObjectNode();
        role.put("readonly", true);
        role.set("cluster", clusterPermissionsArrayNode);
        role.set("indices", indexPermission);

        return role;
    }

    final ConfigModel configModel;

    public SecurityRolesPermissionsV6Test() throws IOException {
        this.configModel = new ConfigModelV6(
            createRolesConfig(),
            createRoleMappingsConfig(),
            createActionGroupsConfig(),
            mock(DynamicConfigModel.class),
            Settings.EMPTY
        );
    }

    @Test
    public void hasExplicitIndexPermission() {
        IndexNameExpressionResolver resolver = mock(IndexNameExpressionResolver.class);
        User user = new User("test");
        ClusterService cs = mock(ClusterService.class);
        doReturn(createClusterState(new IndexShorthand(TEST_INDEX, IndexAbstraction.Type.ALIAS))).when(cs).state();
        IndexResolverReplacer.Resolved resolved = createResolved(TEST_INDEX);

        // test hasExplicitIndexPermission
        final SecurityRoles securityRoleWithStarAccess = configModel.getSecurityRoles()
            .filter(ImmutableSet.of("all_access_without_system_index_permission"));
        user.addSecurityRoles(List.of("all_access_without_system_index_permission"));

        Assert.assertFalse(
            "Should not allow system index access with * only",
            securityRoleWithStarAccess.hasExplicitIndexPermission(resolved, user, new String[] {}, resolver, cs)
        );

        final SecurityRoles securityRoleWithExplicitAccess = configModel.getSecurityRoles()
            .filter(ImmutableSet.of("has_system_index_permission"));
        user.addSecurityRoles(List.of("has_system_index_permission"));

        Assert.assertTrue(
            "Should allow system index access with explicit only",
            securityRoleWithExplicitAccess.hasExplicitIndexPermission(resolved, user, new String[] {}, resolver, cs)
        );
    }

    @Test
    public void isPermittedOnSystemIndex() {
        final SecurityRoles securityRoleWithExplicitAccess = configModel.getSecurityRoles()
            .filter(ImmutableSet.of("has_system_index_permission"));
        Assert.assertTrue(securityRoleWithExplicitAccess.isPermittedOnSystemIndex(TEST_INDEX));

        final SecurityRoles securityRoleWithStarAccess = configModel.getSecurityRoles()
            .filter(ImmutableSet.of("all_access_without_system_index_permission"));
        Assert.assertFalse(securityRoleWithStarAccess.isPermittedOnSystemIndex(TEST_INDEX));
    }

    static <T> SecurityDynamicConfiguration<T> createRolesConfig() throws IOException {
        final ObjectNode rolesNode = DefaultObjectMapper.objectMapper.createObjectNode();
        NO_EXPLICIT_SYSTEM_INDEX_PERMISSION.forEach(rolesNode::set);
        HAS_SYSTEM_INDEX_PERMISSION.forEach(rolesNode::set);
        return SecurityDynamicConfiguration.fromNode(rolesNode, CType.ROLES, 1, 0, 0);
    }

    static <T> SecurityDynamicConfiguration<T> createRoleMappingsConfig() throws IOException {
        final ObjectNode metaNode = DefaultObjectMapper.objectMapper.createObjectNode();
        return SecurityDynamicConfiguration.fromNode(metaNode, CType.ROLESMAPPING, 1, 0, 0);
    }

    static <T> SecurityDynamicConfiguration<T> createActionGroupsConfig() throws IOException {
        final ObjectNode metaNode = DefaultObjectMapper.objectMapper.createObjectNode();
        return SecurityDynamicConfiguration.fromNode(metaNode, CType.ACTIONGROUPS, 1, 0, 0);
    }

    private IndexResolverReplacer.Resolved createResolved(final String... indexes) {
        return new IndexResolverReplacer.Resolved(
            ImmutableSet.of(),
            ImmutableSet.copyOf(indexes),
            ImmutableSet.copyOf(indexes),
            ImmutableSet.of(),
            IndicesOptions.STRICT_EXPAND_OPEN
        );
    }

    private ClusterState createClusterState(final IndexShorthand... indices) {
        final TreeMap<String, IndexAbstraction> indexMap = new TreeMap<String, IndexAbstraction>();
        Arrays.stream(indices).forEach(indexShorthand -> {
            final IndexAbstraction indexAbstraction = mock(IndexAbstraction.class);
            when(indexAbstraction.getType()).thenReturn(indexShorthand.type);
            indexMap.put(indexShorthand.name, indexAbstraction);
        });

        final Metadata mockMetadata = mock(Metadata.class, withSettings().strictness(Strictness.LENIENT));
        when(mockMetadata.getIndicesLookup()).thenReturn(indexMap);

        final ClusterState mockClusterState = mock(ClusterState.class, withSettings().strictness(Strictness.LENIENT));
        when(mockClusterState.getMetadata()).thenReturn(mockMetadata);

        return mockClusterState;
    }

    private class IndexShorthand {
        public final String name;
        public final IndexAbstraction.Type type;

        public IndexShorthand(final String name, final IndexAbstraction.Type type) {
            this.name = name;
            this.type = type;
        }
    }
}
