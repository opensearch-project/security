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
import org.opensearch.security.securityconf.impl.v7.RoleV7;

import org.mockito.Mockito;

import static org.junit.Assert.assertEquals;
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
    public void isNotAllowedRightsToChangeImmutableEntity() throws Exception {
        final var role = new RoleV7();
        role.setCluster_permissions(restApiAdminPermissions());

        when(configuration.exists("sss")).thenReturn(true);
        Mockito.<Object>when(configuration.getCEntry("sss")).thenReturn(role);

        when(restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();
        final var rolesApiActionEndpointValidator = new RolesApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator();
        final var result = rolesApiActionEndpointValidator.isAllowedToChangeImmutableEntity(SecurityConfiguration.of("sss", configuration));

        assertFalse(result.isValid());
        assertEquals(RestStatus.FORBIDDEN, result.status());
    }

}
