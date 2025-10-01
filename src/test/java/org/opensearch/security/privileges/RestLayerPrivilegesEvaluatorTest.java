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

package org.opensearch.security.privileges;

import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.privileges.actionlevel.RuntimeOptimizedActionPrivileges;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;

import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@RunWith(MockitoJUnitRunner.class)
public class RestLayerPrivilegesEvaluatorTest {

    private static final User TEST_USER = new User("test_user").withSecurityRoles(Set.of("test_role"));

    @Test
    public void testEvaluate_Initialized_Success() throws Exception {
        String action = "action";
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
            "  cluster_permissions:\n" + //
            "  - any", CType.ROLES);

        PrivilegesConfiguration privilegesConfiguration = createPrivilegesConfiguration(roles);
        RestLayerPrivilegesEvaluator restPrivilegesEvaluator = new RestLayerPrivilegesEvaluator(privilegesConfiguration);

        PrivilegesEvaluatorResponse response = restPrivilegesEvaluator.evaluate(TEST_USER, "route_name", Set.of(action));

        assertThat(response.isAllowed(), equalTo(false));
        assertThat(response.getMissingPrivileges(), equalTo(Set.of(action)));
    }

    @Test
    public void testEvaluate_Successful_NewPermission() throws Exception {
        String action = "hw:greet";
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
            "  cluster_permissions:\n" + //
            "  - hw:greet", CType.ROLES);
        PrivilegesConfiguration privilegesConfiguration = createPrivilegesConfiguration(roles);
        RestLayerPrivilegesEvaluator restPrivilegesEvaluator = new RestLayerPrivilegesEvaluator(privilegesConfiguration);
        PrivilegesEvaluatorResponse response = restPrivilegesEvaluator.evaluate(TEST_USER, "route_name", Set.of(action));
        assertThat(response.allowed, equalTo(true));
    }

    @Test
    public void testEvaluate_Successful_LegacyPermission() throws Exception {
        String action = "cluster:admin/opensearch/hw/greet";
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
            "  cluster_permissions:\n" + //
            "  - cluster:admin/opensearch/hw/greet", CType.ROLES);
        PrivilegesConfiguration privilegesConfiguration = createPrivilegesConfiguration(roles);
        RestLayerPrivilegesEvaluator restPrivilegesEvaluator = new RestLayerPrivilegesEvaluator(privilegesConfiguration);
        PrivilegesEvaluatorResponse response = restPrivilegesEvaluator.evaluate(TEST_USER, "route_name", Set.of(action));
        assertThat(response.allowed, equalTo(true));
    }

    @Test
    public void testEvaluate_Unsuccessful() throws Exception {
        String action = "action";
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
            "  cluster_permissions:\n" + //
            "  - other_action", CType.ROLES);
        PrivilegesConfiguration privilegesConfiguration = createPrivilegesConfiguration(roles);
        RestLayerPrivilegesEvaluator restPrivilegesEvaluator = new RestLayerPrivilegesEvaluator(privilegesConfiguration);
        PrivilegesEvaluatorResponse response = restPrivilegesEvaluator.evaluate(TEST_USER, "route_name", Set.of(action));
        assertThat(response.allowed, equalTo(false));
    }

    PrivilegesConfiguration createPrivilegesConfiguration(SecurityDynamicConfiguration<RoleV7> roles) {
        return new PrivilegesConfiguration(createPrivilegesEvaluator(roles));
    }

    PrivilegesEvaluator createPrivilegesEvaluator(SecurityDynamicConfiguration<RoleV7> roles) {
        ActionPrivileges actionPrivileges = new RoleBasedActionPrivileges(
            roles,
            FlattenedActionGroups.EMPTY,
            RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE,
            Settings.EMPTY,
            false
        );

        return new PrivilegesEvaluator() {

            @Override
            public PrivilegesEvaluationContext createContext(
                User user,
                String action,
                ActionRequest actionRequest,
                ActionRequestMetadata<?, ?> actionRequestMetadata,
                Task task
            ) {
                return new PrivilegesEvaluationContext(
                    user,
                    user.getSecurityRoles(),
                    action,
                    actionRequest,
                    ActionRequestMetadata.empty(),
                    task,
                    null,
                    null,
                    null,
                    actionPrivileges
                );
            }

            @Override
            public PrivilegesEvaluatorResponse evaluate(PrivilegesEvaluationContext context) {
                return null;
            }

            @Override
            public boolean isClusterPermission(String action) {
                return false;
            }

            @Override
            public void updateConfiguration(
                FlattenedActionGroups actionGroups,
                SecurityDynamicConfiguration<RoleV7> rolesConfiguration,
                ConfigV7 generalConfiguration
            ) {

            }

            @Override
            public void updateClusterStateMetadata(ClusterService clusterService) {

            }

            @Override
            public void shutdown() {

            }

            @Override
            public boolean notFailOnForbiddenEnabled() {
                return false;
            }

            @Override
            public boolean isInitialized() {
                return true;
            }
        };

    }

}
