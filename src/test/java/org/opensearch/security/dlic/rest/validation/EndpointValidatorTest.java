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

package org.opensearch.security.dlic.rest.validation;

import org.apache.commons.lang3.tuple.Triple;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator;
import org.opensearch.security.dlic.rest.api.SecurityConfiguration;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EndpointValidatorTest {

    @Mock
    SecurityDynamicConfiguration<?> configuration;

    @Mock
    RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator;

    private EndpointValidator endpointValidator;

    @Before
    public void createConfigurationValidator() {
        endpointValidator = new EndpointValidator() {
            @Override
            public String resourceName() {
                return "resource";
            }

            @Override
            public Endpoint endpoint() {
                return Endpoint.INTERNALUSERS;
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return restApiAdminPrivilegesEvaluator;
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.NOOP_VALIDATOR;
            }
        };
    }

    @Test
    public void entityDoesNotExist() {
        when(configuration.exists("some_role")).thenReturn(false);
        final var validationResult = endpointValidator.entityExists(SecurityConfiguration.of("some_role", configuration));
        assertFalse(validationResult.isValid());
        assertEquals(RestStatus.NOT_FOUND, validationResult.status());
    }

    @Test
    public void entityExists() {
        when(configuration.exists("some_role")).thenReturn(true);
        final var validationResult = endpointValidator.entityExists(SecurityConfiguration.of("some_role", configuration));
        assertTrue(validationResult.isValid());
        assertEquals(RestStatus.OK, validationResult.status());
    }

    @Test
    public void entityExistsSkipEmptyEntityName() {
        when(configuration.exists(null)).thenReturn(false);
        final var validationResult = endpointValidator.entityExists(SecurityConfiguration.of(null, configuration));
        assertTrue(validationResult.isValid());
        assertEquals(RestStatus.OK, validationResult.status());
    }

    @Test
    public void entityHidden() {
        when(configuration.isHidden("some_entity")).thenReturn(true);
        final var validationResult = endpointValidator.entityHidden( SecurityConfiguration.of("some_entity", configuration));
        assertFalse(validationResult.isValid());
        assertEquals(RestStatus.NOT_FOUND, validationResult.status());
    }

    @Test
    public void entityNotHidden() {
        when(configuration.isHidden("some_entity")).thenReturn(false);
        final var validationResult = endpointValidator.entityHidden( SecurityConfiguration.of("some_entity", configuration));
        assertTrue(validationResult.isValid());
        assertEquals(RestStatus.OK, validationResult.status());
    }

    @Test
    public void entityReserved() {
        when(configuration.isReserved("some_entity")).thenReturn(true);
        final var validationResult = endpointValidator.entityReserved( SecurityConfiguration.of("some_entity", configuration));
        assertFalse(validationResult.isValid());
        assertEquals(RestStatus.FORBIDDEN, validationResult.status());
    }

    @Test
    public void entityNotReserved() {
        when(configuration.isReserved("some_entity")).thenReturn(false);
        final var validationResult = endpointValidator.entityReserved( SecurityConfiguration.of("some_entity", configuration));
        assertTrue(validationResult.isValid());
        assertEquals(RestStatus.OK, validationResult.status());
    }

    @Test
    public void entityStatic() {
        when(configuration.isStatic("some_entity")).thenReturn(true);
        final var validationResult = endpointValidator.entityStatic( SecurityConfiguration.of("some_entity", configuration));
        assertFalse(validationResult.isValid());
        assertEquals(RestStatus.FORBIDDEN, validationResult.status());
    }

    @Test
    public void entityNotStatic() {
        when(configuration.isStatic("some_entity")).thenReturn(false);
        final var validationResult = endpointValidator.entityStatic( SecurityConfiguration.of("some_entity", configuration));
        assertTrue(validationResult.isValid());
        assertEquals(RestStatus.OK, validationResult.status());
    }

    @Test
    public void hiddenEntityImmutable() throws Exception {
        when(configuration.isHidden("some_entity")).thenReturn(true);

        var validationResult = endpointValidator.entityImmutable( SecurityConfiguration.of("some_entity", configuration));
        assertFalse(validationResult.isValid());
        assertEquals(RestStatus.NOT_FOUND, validationResult.status());
    }

    @Test
    public void staticEntityImmutable() throws Exception {
        when(configuration.isHidden("some_entity")).thenReturn(false);
        when(configuration.isStatic("some_entity")).thenReturn(true);
        final var validationResult = endpointValidator.entityImmutable( SecurityConfiguration.of("some_entity", configuration));
        assertFalse(validationResult.isValid());
        assertEquals(RestStatus.FORBIDDEN, validationResult.status());
    }

    @Test
    public void reservedEntityImmutable() throws Exception {
        when(configuration.isHidden("some_entity")).thenReturn(false);
        when(configuration.isStatic("some_entity")).thenReturn(false);
        when(configuration.isReserved("some_entity")).thenReturn(true);
        final var validationResult = endpointValidator.entityImmutable( SecurityConfiguration.of("some_entity", configuration));
        assertFalse(validationResult.isValid());
        assertEquals(RestStatus.FORBIDDEN, validationResult.status());
    }

    @Test
    public void hasRightsToChangeImmutableEntity() throws Exception {
        configImmutableEntities(false);
        var result = endpointValidator.hasRightsToChangeEntity(SecurityConfiguration.of("hidden_entity", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.NOT_FOUND, result.status());

        result = endpointValidator.hasRightsToChangeEntity(SecurityConfiguration.of("static_entity", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.FORBIDDEN, result.status());

        result = endpointValidator.hasRightsToChangeEntity(SecurityConfiguration.of("reserved_entity", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.FORBIDDEN, result.status());

        result = endpointValidator.hasRightsToChangeEntity(SecurityConfiguration.of("just_entity", configuration));
        assertTrue(result.isValid());
        assertEquals(RestStatus.OK, result.status());
    }

    @Test
    public void hasRightsToChangeImmutableEntityForAdmin() throws Exception {
        configImmutableEntities(true);

        var result = endpointValidator.hasRightsToChangeEntity(SecurityConfiguration.of("hidden_entity", configuration));
        assertTrue(result.isValid());
        assertEquals(RestStatus.OK, result.status());

        result = endpointValidator.hasRightsToChangeEntity(SecurityConfiguration.of("static_entity", configuration));
        assertTrue(result.isValid());
        assertEquals(RestStatus.OK, result.status());

        result = endpointValidator.hasRightsToChangeEntity(SecurityConfiguration.of("reserved_entity", configuration));
        assertTrue(result.isValid());
        assertEquals(RestStatus.OK, result.status());

        result = endpointValidator.hasRightsToChangeEntity(SecurityConfiguration.of("just_entity", configuration));
        assertTrue(result.isValid());
        assertEquals(RestStatus.OK, result.status());
    }

    @Test
    public void hasRightsToLoadOrChangeHiddenEntityForRegularUser() throws Exception {
        configImmutableEntities(false);

        var result = endpointValidator.hasRightsToLoadOrChangeHiddenEntity(SecurityConfiguration.of("hidden_entity", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.NOT_FOUND, result.status());

        result = endpointValidator.hasRightsToLoadOrChangeHiddenEntity(SecurityConfiguration.of("just_entity", configuration));
        assertTrue(result.isValid());
        assertEquals(RestStatus.OK, result.status());
    }

    @Test
    public void hasRightsToLoadOrChangeHiddenEntityForAdmin() throws Exception {
        configImmutableEntities(true);

        var result = endpointValidator.hasRightsToLoadOrChangeHiddenEntity(SecurityConfiguration.of("hidden_entity", configuration));
        assertTrue(result.isValid());
        assertEquals(RestStatus.OK, result.status());

        result = endpointValidator.hasRightsToLoadOrChangeHiddenEntity(SecurityConfiguration.of("just_entity", configuration));
        assertTrue(result.isValid());
        assertEquals(RestStatus.OK, result.status());
    }

    private void configImmutableEntities(final boolean isAdmin) {
        when(restApiAdminPrivilegesEvaluator.isCurrentUserAdminFor(any(Endpoint.class))).thenReturn(isAdmin);
        when(configuration.isHidden("just_entity")).thenReturn(false);
        when(configuration.isStatic("just_entity")).thenReturn(false);
        when(configuration.isReserved("just_entity")).thenReturn(false);

        when(configuration.isHidden("hidden_entity")).thenReturn(true);
        when(configuration.isStatic("static_entity")).thenReturn(true);
        when(configuration.isReserved("reserved_entity")).thenReturn(true);
    }

    @Test
    public void entityNotImmutable() throws Exception {
        when(configuration.isHidden("some_entity")).thenReturn(false);
        when(configuration.isStatic("some_entity")).thenReturn(false);
        when(configuration.isReserved("some_entity")).thenReturn(false);

        var validationResult = endpointValidator.entityImmutable( SecurityConfiguration.of("some_entity", configuration));
        assertTrue(validationResult.isValid());
        assertEquals(RestStatus.OK, validationResult.status());
    }

    @Test
    public void validateRolesForAdmin() {
        configureRoles(true);
        final var expectedResultForRoles = List.of(
            Triple.of("valid_role", true, RestStatus.OK),
            Triple.of("reserved_role", true, RestStatus.OK),
            Triple.of("static_role", true, RestStatus.OK),
            Triple.of("hidden_role", true, RestStatus.OK),
            Triple.of("non_existing_role", false, RestStatus.NOT_FOUND)
        );

        for (final var roleWithExpectedResults : expectedResultForRoles) {
            final var validationResult = endpointValidator.validateRoles(List.of(roleWithExpectedResults.getLeft()), configuration);
            assertEquals(roleWithExpectedResults.getMiddle(), validationResult.isValid());
            assertEquals(roleWithExpectedResults.getRight(), validationResult.status());
        }

    }

    @Test
    public void validateRolesForRegularUser() {
        configureRoles(false);
        final var expectedResultForRoles = List.of(
            Triple.of("valid_role", true, RestStatus.OK),
            Triple.of("reserved_role", false, RestStatus.FORBIDDEN),
            Triple.of("static_role", false, RestStatus.FORBIDDEN),
            Triple.of("hidden_role", false, RestStatus.NOT_FOUND),
            Triple.of("non_existing_role", false, RestStatus.NOT_FOUND)
        );

        for (final var roleWithExpectedResults : expectedResultForRoles) {
            final var validationResult = endpointValidator.validateRoles(List.of(roleWithExpectedResults.getLeft()), configuration);
            assertEquals(roleWithExpectedResults.getMiddle(), validationResult.isValid());
            assertEquals(roleWithExpectedResults.getRight(), validationResult.status());
        }

    }

    private void configureRoles(final boolean isAdmin) {
        when(restApiAdminPrivilegesEvaluator.isCurrentUserAdminFor(any(Endpoint.class))).thenReturn(isAdmin);

        when(configuration.exists("non_existing_role")).thenReturn(false);

        when(configuration.exists("hidden_role")).thenReturn(true);
        when(configuration.isHidden("hidden_role")).thenReturn(true);

        when(configuration.exists("static_role")).thenReturn(true);
        when(configuration.isHidden("static_role")).thenReturn(false);
        when(configuration.isStatic("static_role")).thenReturn(true);

        when(configuration.exists("reserved_role")).thenReturn(true);
        when(configuration.isHidden("reserved_role")).thenReturn(false);
        when(configuration.isStatic("reserved_role")).thenReturn(false);
        when(configuration.isReserved("reserved_role")).thenReturn(true);

        when(configuration.exists("valid_role")).thenReturn(true);
        when(configuration.isHidden("valid_role")).thenReturn(false);
        when(configuration.isStatic("valid_role")).thenReturn(false);
        when(configuration.isReserved("valid_role")).thenReturn(false);
    }

    @Test
    public void regularUserCanNotChangeObjectWithRestAdminPermissions() throws Exception {
        final var restAdminPermissions = List.of(
            "restapi:admin/actiongroups",
            "restapi:admin/allowlist",
            "restapi:admin/internalusers",
            "restapi:admin/nodesdn",
            "restapi:admin/roles",
            "restapi:admin/rolesmapping",
            "restapi:admin/ssl/certs/info",
            "restapi:admin/ssl/certs/reload",
            "restapi:admin/tenants"
        );

        final var actionGroups = new ActionGroupsV7("some_ag", restAdminPermissions);
        final var role = new RoleV7();
        role.setCluster_permissions(restAdminPermissions);

        when(configuration.exists("some_ag")).thenReturn(true);
        when(restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();
        Mockito.<Object>when(configuration.getCEntry("some_ag")).thenReturn(actionGroups);
        var agCheckResult = endpointValidator.canChangeObjectWithRestAdminPermissions(SecurityConfiguration.of("some_ag", configuration));
        assertFalse(agCheckResult.isValid());
        assertEquals(RestStatus.FORBIDDEN, agCheckResult.status());

        reset(restApiAdminPrivilegesEvaluator, configuration);

        when(configuration.exists("some_role")).thenReturn(true);
        when(restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(any(Object.class))).thenCallRealMethod();
        Mockito.<Object>when(configuration.getCEntry("some_role")).thenReturn(role);
        final var roleCheckResult = endpointValidator.canChangeObjectWithRestAdminPermissions(
            SecurityConfiguration.of("some_role", configuration)
        );
        assertFalse(roleCheckResult.isValid());
        assertEquals(RestStatus.FORBIDDEN, roleCheckResult.status());
    }

}
