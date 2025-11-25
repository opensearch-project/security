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

package org.opensearch.security.action.apitokens;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration.fromMap;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ApiTokenActionTest {
    @Mock
    private ThreadPool threadPool;

    @Mock
    private PrivilegesConfiguration privilegesConfiguration;

    @Mock
    private ConfigurationRepository configurationRepository;

    @Mock
    private ClusterService clusterService;
    @Mock
    private ClusterState clusterState;

    @Mock
    private Metadata metadata;

    private SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsConfig;
    private SecurityDynamicConfiguration<RoleV7> rolesConfig;
    private FlattenedActionGroups flattenedActionGroups;
    private ApiTokenAction apiTokenAction;

    @Before
    public void setUp() throws JsonProcessingException {
        // Setup basic action groups

        actionGroupsConfig = SecurityDynamicConfiguration.fromMap(
            ImmutableMap.of(
                "read_group",
                Map.of("allowed_actions", List.of("read", "get", "search")),
                "write_group",
                Map.of("allowed_actions", List.of("write", "create", "index"))
            ),
            CType.ACTIONGROUPS
        );

        rolesConfig = fromMap(
            ImmutableMap.of(
                "read_group_logs-123",
                ImmutableMap.of(
                    "index_permissions",
                    Arrays.asList(ImmutableMap.of("index_patterns", List.of("logs-123"), "allowed_actions", List.of("read_group"))),
                    "cluster_permissions",
                    Arrays.asList("*")
                ),
                "read_group_logs-star",
                ImmutableMap.of(
                    "index_permissions",
                    Arrays.asList(ImmutableMap.of("index_patterns", List.of("logs-*"), "allowed_actions", List.of("read_group"))),
                    "cluster_permissions",
                    Arrays.asList("*")
                ),
                "write_group_logs-star",
                ImmutableMap.of(
                    "index_permissions",
                    Arrays.asList(ImmutableMap.of("index_patterns", List.of("logs-*"), "allowed_actions", List.of("write_group"))),
                    "cluster_permissions",
                    Arrays.asList("*")
                ),
                "write_group_logs-123",
                ImmutableMap.of(
                    "index_permissions",
                    Arrays.asList(ImmutableMap.of("index_patterns", List.of("logs-123"), "allowed_actions", List.of("write_group"))),
                    "cluster_permissions",
                    Arrays.asList("*")
                ),
                "more_permissable_write_group_lo-star",
                ImmutableMap.of(
                    "index_permissions",
                    Arrays.asList(ImmutableMap.of("index_patterns", List.of("lo*"), "allowed_actions", List.of("write_group"))),
                    "cluster_permissions",
                    Arrays.asList("*")
                ),
                "cluster_monitor",
                ImmutableMap.of(
                    "index_permissions",
                    Arrays.asList(ImmutableMap.of("index_patterns", List.of("lo*"), "allowed_actions", List.of("write_group"))),
                    "cluster_permissions",
                    Arrays.asList("cluster_monitor")
                ),
                "alias_group",
                ImmutableMap.of(
                    "index_permissions",
                    Arrays.asList(ImmutableMap.of("index_patterns", List.of("logs"), "allowed_actions", List.of("read"))),
                    "cluster_permissions",
                    Arrays.asList("cluster_monitor")
                )

            ),
            CType.ROLES
        );

        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));

        apiTokenAction = new ApiTokenAction(

            threadPool,
            configurationRepository,
            privilegesConfiguration,
            Settings.EMPTY,
            null,
            null,
            null,
            null,
            null,
            clusterService,
            null,
            null
        );

    }

    @Test
    public void testCreateIndexPermission() {
        Map<String, Object> validPermission = new HashMap<>();
        validPermission.put("index_pattern", "test-*");
        validPermission.put("allowed_actions", List.of("read"));

        ApiToken.IndexPermission result = apiTokenAction.createIndexPermission(validPermission);

        assertThat(result.getIndexPatterns(), is(List.of("test-*")));
        assertThat(result.getAllowedActions(), is(List.of("read")));
    }

    @Test
    public void testValidateRequestParameters() {
        Map<String, Object> validRequest = new HashMap<>();
        validRequest.put("name", "test-token");
        validRequest.put("cluster_permissions", Arrays.asList("perm1", "perm2"));
        apiTokenAction.validateRequestParameters(validRequest);

        // Missing name
        Map<String, Object> missingName = new HashMap<>();
        assertThrows(IllegalArgumentException.class, () -> apiTokenAction.validateRequestParameters(missingName));

        // Invalid cluster_permissions type
        Map<String, Object> invalidClusterPerms = new HashMap<>();
        invalidClusterPerms.put("name", "test");
        invalidClusterPerms.put("cluster_permissions", "not a list");
        assertThrows(IllegalArgumentException.class, () -> apiTokenAction.validateRequestParameters(invalidClusterPerms));
    }

    @Test
    public void testValidateIndexPermissionsList() {
        Map<String, Object> validPerm = new HashMap<>();
        validPerm.put("index_pattern", "test-*");
        validPerm.put("allowed_actions", List.of("read"));
        apiTokenAction.validateIndexPermissionsList(Collections.singletonList(validPerm));

        // Missing index_pattern
        Map<String, Object> missingPattern = new HashMap<>();
        missingPattern.put("allowed_actions", List.of("read"));
        assertThrows(
            IllegalArgumentException.class,
            () -> apiTokenAction.validateIndexPermissionsList(Collections.singletonList(missingPattern))
        );

        // Missing allowed_actions
        Map<String, Object> missingActions = new HashMap<>();
        missingActions.put("index_pattern", "test-*");
        assertThrows(
            IllegalArgumentException.class,
            () -> apiTokenAction.validateIndexPermissionsList(Collections.singletonList(missingActions))
        );

        // Invalid index_pattern type
        Map<String, Object> invalidPattern = new HashMap<>();
        invalidPattern.put("index_pattern", 123);
        invalidPattern.put("allowed_actions", List.of("read"));
        assertThrows(
            IllegalArgumentException.class,
            () -> apiTokenAction.validateIndexPermissionsList(Collections.singletonList(invalidPattern))
        );
    }

    @Test
    public void testExtractClusterPermissions() {
        Map<String, Object> requestBody = new HashMap<>();

        assertThat(apiTokenAction.extractClusterPermissions(requestBody), is(empty()));

        requestBody.put("cluster_permissions", Arrays.asList("perm1", "perm2"));
        assertThat(apiTokenAction.extractClusterPermissions(requestBody), is(Arrays.asList("perm1", "perm2")));
    }
}
