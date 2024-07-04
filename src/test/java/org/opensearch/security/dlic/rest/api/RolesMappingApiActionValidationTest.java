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
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.securityconf.impl.CType;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class RolesMappingApiActionValidationTest extends AbstractApiActionValidationTest {

    @Before
    public void setupRoles() throws Exception {
        setupRolesConfiguration();
    }

    @Test
    public void isAllowedRightsToChangeRoleEntity() throws Exception {
        final var rolesMappingApiActionEndpointValidator = new RolesMappingApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator();
        final var result = rolesMappingApiActionEndpointValidator.isAllowedToChangeImmutableEntity(
            SecurityConfiguration.of("rest_api_admin_role", configuration)
        );
        assertTrue(result.isValid());
    }

    @Test
    public void isNotAllowedNoRightsToChangeRoleEntity() throws Exception {
        when(restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();

         final var rolesApiActionEndpointValidator =
                 new RolesMappingApiAction(clusterService, threadPool,
                         securityApiDependencies).createEndpointValidator();
         final var result = rolesApiActionEndpointValidator.isAllowedToChangeImmutableEntity(
                 SecurityConfiguration.of("rest_api_admin_role", configuration));

         assertFalse(result.isValid());
         assertThat(result.status(), is(RestStatus.FORBIDDEN));
    }

    @Test
    public void onConfigChangeShouldCheckRoles() throws Exception {
        when(restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();
        when(configurationRepository.getConfigurationsFromIndex(List.of(CType.ROLES), false))
                .thenReturn(Map.of(CType.ROLES, rolesConfiguration));
        final var rolesApiActionEndpointValidator =
                new RolesMappingApiAction(clusterService, threadPool,
                        securityApiDependencies).createEndpointValidator();

        // no role
        var result = rolesApiActionEndpointValidator.onConfigChange(SecurityConfiguration.of("aaa", configuration));
        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.NOT_FOUND));
        //static role is ok
        result = rolesApiActionEndpointValidator.onConfigChange(SecurityConfiguration.of("all_access", configuration));
        assertTrue(result.isValid());
        //reserved role is ok
        result = rolesApiActionEndpointValidator.onConfigChange(SecurityConfiguration.of("kibana_read_only", configuration));
        assertTrue(result.isValid());
        //just regular_role
        result = rolesApiActionEndpointValidator.onConfigChange(SecurityConfiguration.of("regular_role", configuration));
        assertTrue(result.isValid());
        //hidden role is not ok
        result = rolesApiActionEndpointValidator.onConfigChange(SecurityConfiguration.of("some_hidden_role", configuration));
        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.NOT_FOUND));
    }

}
