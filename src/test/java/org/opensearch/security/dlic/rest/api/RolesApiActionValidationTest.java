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

import org.junit.Test;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class RolesApiActionValidationTest extends AbstractApiActionValidationTest {

    @Test
    public void isAllowedToChangeImmutableEntity() throws Exception {
        final var role = new RoleV7();
        role.setCluster_permissions(restApiAdminPermissions());

        final var rolesApiActionEndpointValidator = new RolesApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator();
        final var result = rolesApiActionEndpointValidator.isAllowedToChangeImmutableEntity(SecurityConfiguration.of("sss", configuration));

        assertTrue(result.isValid());
    }

    @Test
    public void superAdminIsAllowedToCreateRoleWithRestAdminPermissions() throws Exception {
        when(restApiAuthorizationEvaluator.isCurrentUserSuperAdmin()).thenReturn(true);

        final var role = objectMapper.createObjectNode();
        final var clusterPermissions = objectMapper.createArrayNode();
        clusterPermissions.add("restapi:admin/actiongroups");
        clusterPermissions.add("restapi:admin/roles");
        clusterPermissions.add("restapi:admin/rolesmapping");
        role.set("cluster_permissions", clusterPermissions);
        final var rolesApiActionEndpointValidator = new RolesApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator();
        assertTrue(rolesApiActionEndpointValidator.isCurrentUserSuperAdmin());

        final var result = rolesApiActionEndpointValidator.isAllowedToChangeImmutableEntity(
            SecurityConfiguration.of(role, "test_role", configuration)
        );

        assertTrue(result.isValid());
    }
    
    @Test
    public void nonSuperAdminIsNotAllowedToCreateRoleWithRestAdminPermissions() throws Exception {
        when(restApiAuthorizationEvaluator.isCurrentUserSuperAdmin()).thenReturn(false);
        Mockito.doReturn(CType.ROLES).when(configuration).getCType();
        when(configuration.getImplementingClass()).thenCallRealMethod();
        when(restApiAuthorizationEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();

        final var role = objectMapper.createObjectNode();
        final var clusterPermissions = objectMapper.createArrayNode();
        clusterPermissions.add("restapi:admin/actiongroups");
        clusterPermissions.add("restapi:admin/roles");
        clusterPermissions.add("restapi:admin/rolesmapping");
        role.set("cluster_permissions", clusterPermissions);
        final var rolesApiActionEndpointValidator = new RolesApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator();
        assertFalse(rolesApiActionEndpointValidator.isCurrentUserSuperAdmin());

        final var result = rolesApiActionEndpointValidator.isAllowedToChangeImmutableEntity(
            SecurityConfiguration.of(role, "test_role", configuration)
        );

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.FORBIDDEN));
    }

    @Test
    public void isNotAllowedRightsToChangeImmutableEntity() throws Exception {
        final var role = new RoleV7();
        role.setCluster_permissions(restApiAdminPermissions());

        when(configuration.exists("sss")).thenReturn(true);
        Mockito.<Object>when(configuration.getCEntry("sss")).thenReturn(role);

        when(restApiAuthorizationEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();
        final var rolesApiActionEndpointValidator = new RolesApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator();
        final var result = rolesApiActionEndpointValidator.isAllowedToChangeImmutableEntity(SecurityConfiguration.of("sss", configuration));

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.FORBIDDEN));
    }

}
