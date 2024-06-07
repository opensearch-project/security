/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.dlic.rest.api;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;

import org.mockito.Mockito;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class ActionGroupsApiActionValidationTest extends AbstractApiActionValidationTest {

    @Before
    public void setupRoles() throws Exception {
        setupRolesConfiguration();
    }

    @Test
    public void hasNoRightsToChangeImmutableEntityFoAdminUser() throws Exception {
        final var actionGroups = new ActionGroupsV7("ag", restApiAdminPermissions());
        when(configuration.exists("ag")).thenReturn(true);
        Mockito.<Object>when(configuration.getCEntry("ag")).thenReturn(actionGroups);
        when(restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();

        final var actionGroupsApiActionEndpointValidator = new ActionGroupsApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator();

        final var result = actionGroupsApiActionEndpointValidator.isAllowedToChangeImmutableEntity(
            SecurityConfiguration.of("ag", configuration)
        );
        assertFalse(result.isValid());
        assertEquals(RestStatus.FORBIDDEN, result.status());
    }

    @Test
    public void hasNoRightsToChangeImmutableEntityForRegularUser() throws Exception {
        final var actionGroups = new ActionGroupsV7("ag", restApiAdminPermissions());
        when(configuration.exists("ag")).thenReturn(true);
        Mockito.<Object>when(configuration.getCEntry("ag")).thenReturn(actionGroups);
        when(restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();

        final var actionGroupsApiActionEndpointValidator = new ActionGroupsApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator();

        final var result = actionGroupsApiActionEndpointValidator.isAllowedToChangeImmutableEntity(
            SecurityConfiguration.of("ag", configuration)
        );
        assertFalse(result.isValid());
        assertEquals(RestStatus.FORBIDDEN, result.status());
    }

    @Test
    public void onConfigChangeActionGroupHasSameNameAsRole() throws Exception {
        when(configuration.getCType()).thenReturn(CType.ACTIONGROUPS);
        when(configuration.getVersion()).thenReturn(2);
        when(configuration.getImplementingClass()).thenCallRealMethod();
        final var ag = objectMapper.createObjectNode()
                .put("type", ActionGroupsApiAction.CLUSTER_TYPE)
                .set("allowed_actions", objectMapper.createArrayNode().add("indices:*"));
        final var actionGroupsApiActionEndpointValidator = new ActionGroupsApiAction(clusterService, threadPool, securityApiDependencies)
                .createEndpointValidator();

        final var result = actionGroupsApiActionEndpointValidator.onConfigChange(SecurityConfiguration.of(ag,"kibana_read_only", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());
        assertEquals("kibana_read_only is an existing role. A action group cannot be named with an existing role name.", xContentToJsonNode(result.errorMessage()).get("message").asText());
    }

    @Test
    public void onConfigChangeActionGroupHasSelfReference() throws Exception {
        when(configuration.getCType()).thenReturn(CType.ACTIONGROUPS);
        when(configuration.getVersion()).thenReturn(2);
        when(configuration.getImplementingClass()).thenCallRealMethod();
        final var ag = objectMapper.createObjectNode()
                .put("type", ActionGroupsApiAction.INDEX_TYPE)
                .set("allowed_actions", objectMapper.createArrayNode().add("ag"));
        final var actionGroupsApiActionEndpointValidator = new ActionGroupsApiAction(clusterService, threadPool, securityApiDependencies)
                .createEndpointValidator();

        final var result = actionGroupsApiActionEndpointValidator
                .onConfigChange(SecurityConfiguration.of(ag,"ag", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());
        assertEquals("ag cannot be an allowed_action of itself", xContentToJsonNode(result.errorMessage()).get("message").asText());
    }

    @Test
    public void validateInvalidType() throws Exception {
        when(configuration.getCType()).thenReturn(CType.ACTIONGROUPS);
        when(configuration.getVersion()).thenReturn(2);
        when(configuration.getImplementingClass()).thenCallRealMethod();
        final var ag = objectMapper.createObjectNode()
                .put("type", "some_type_we_know_nothing_about")
                .set("allowed_actions", objectMapper.createArrayNode().add("ag"));
        final var actionGroupsApiActionEndpointValidator = new ActionGroupsApiAction(clusterService, threadPool, securityApiDependencies)
                .createEndpointValidator();

        final var result = actionGroupsApiActionEndpointValidator
                .onConfigChange(SecurityConfiguration.of(ag,"ag", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());
        assertEquals("Invalid action group type: some_type_we_know_nothing_about. Supported types are: cluster, index.", xContentToJsonNode(result.errorMessage()).get("message").asText());
    }

    @Test
    public void passActionGroupWithoutType() throws Exception {
        when(configuration.getCType()).thenReturn(CType.ACTIONGROUPS);
        when(configuration.getVersion()).thenReturn(2);
        when(configuration.getImplementingClass()).thenCallRealMethod();
        final var ag = objectMapper.createObjectNode()
                .set("allowed_actions", objectMapper.createArrayNode().add("ag"));
        final var actionGroupsApiActionEndpointValidator = new ActionGroupsApiAction(clusterService, threadPool, securityApiDependencies)
                .createEndpointValidator();

        final var result = actionGroupsApiActionEndpointValidator
                .onConfigChange(SecurityConfiguration.of(ag,"some_ag", configuration));
        assertTrue(result.isValid());
    }

}
