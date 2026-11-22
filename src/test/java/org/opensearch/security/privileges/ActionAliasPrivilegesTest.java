/* SPDX-License-Identifier: Apache-2.0 */
package org.opensearch.security.privileges;

import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.privileges.actionlevel.RuntimeOptimizedActionPrivileges;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ActionAliasPrivilegesTest {
    private static final String CANONICAL = "report_instance:get";
    private static final String LEGACY = "cluster:admin/opendistro/reports/instance/get";

    @Test
    public void oldAndNewPermissionsAuthorizeEitherRegisteredName() throws Exception {
        for (String granted : List.of(CANONICAL, LEGACY, "cluster:admin/opendistro/reports/instance/*")) {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml(
                "reader:\n  cluster_permissions:\n    - '" + granted + "'\n",
                CType.ROLES
            );
            ActionPrivileges privileges = new RoleBasedActionPrivileges(
                new CompiledRoles(roles, FlattenedActionGroups.EMPTY, NamedXContentRegistry.EMPTY, FieldMasking.Config.DEFAULT, false),
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE,
                Settings.EMPTY,
                false
            );
            for (String invoked : List.of(CANONICAL, LEGACY)) {
                var context = context(invoked, metadata(), privileges);
                assertTrue(privileges.hasClusterPrivilege(context, invoked).isAllowed());
                assertFalse(privileges.hasClusterPrivilege(context, "cluster:admin/unrelated/delete").isAllowed());
            }
        }
    }

    @Test
    public void absentOrUnrelatedMetadataDoesNotExpandPermissions() {
        assertEquals(
            Set.of(CANONICAL),
            context(CANONICAL, ActionRequestMetadata.empty(), ActionPrivileges.EMPTY).getActionNames(CANONICAL)
        );
        assertEquals(
            Set.of("different:action"),
            context("different:action", metadata(), ActionPrivileges.EMPTY).getActionNames("different:action")
        );
    }

    private ActionRequestMetadata<?, ?> metadata() {
        ActionRequestMetadata<?, ?> metadata = mock(ActionRequestMetadata.class);
        when(metadata.canonicalActionName()).thenReturn(CANONICAL);
        when(metadata.legacyActionNames()).thenReturn(Set.of(LEGACY));
        return metadata;
    }

    private PrivilegesEvaluationContext context(String action, ActionRequestMetadata<?, ?> metadata, ActionPrivileges privileges) {
        return new PrivilegesEvaluationContext(
            new User("reader"),
            ImmutableSet.of("reader"),
            action,
            null,
            metadata,
            null,
            null,
            null,
            null,
            privileges,
            List.of()
        );
    }
}
