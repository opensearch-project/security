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

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.hasher.BCryptPasswordHasher;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.UserService;
import org.opensearch.security.util.FakeRestRequest;

import org.mockito.Mock;
import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

public class InternalUsersApiActionValidationTest extends AbstractApiActionValidationTest {

    @Mock
    UserService userService;

    @Mock
    SecurityDynamicConfiguration<?> configuration;

    @Before
    public void setupRolesAndMappings() throws IOException {
        setupRolesConfiguration();

        final var allClusterPermissions = new RoleV7();
        allClusterPermissions.setCluster_permissions(List.of("*"));
        @SuppressWarnings("unchecked")
        final var c = (SecurityDynamicConfiguration<RoleV7>) rolesConfiguration;
        c.putCEntry("some_role_with_static_mapping", allClusterPermissions);
        c.putCEntry("some_role_with_reserved_mapping", allClusterPermissions);
        c.putCEntry("some_role_with_hidden_mapping", allClusterPermissions);

        final var objectMapper = DefaultObjectMapper.objectMapper;
        final var config = objectMapper.createObjectNode();
        config.set("_meta", objectMapper.createObjectNode().put("type", CType.ROLESMAPPING.toLCString()).put("config_version", 2));
        config.set("kibana_read_only", objectMapper.createObjectNode());
        config.set("some_hidden_role", objectMapper.createObjectNode());
        config.set("all_access", objectMapper.createObjectNode());
        config.set("regular_role", objectMapper.createObjectNode());

        config.set("some_role_with_static_mapping", objectMapper.createObjectNode().put("static", true));
        config.set("some_role_with_reserved_mapping", objectMapper.createObjectNode().put("reserved", true));
        config.set("some_role_with_hidden_mapping", objectMapper.createObjectNode().put("hidden", true));

        final var rolesMappingConfiguration = SecurityDynamicConfiguration.fromJson(
            objectMapper.writeValueAsString(config),
            CType.ROLES,
            2,
            1,
            1
        );
        when(configurationRepository.getConfigurationsFromIndex(List.of(CType.ROLESMAPPING), false)).thenReturn(
            Map.of(CType.ROLESMAPPING, rolesMappingConfiguration)
        );
    }

    @Test
    public void replacePasswordWithHash() throws Exception {
        final var internalUsersApiActionEndpointValidator = createInternalUsersApiAction().createEndpointValidator();
        final var securityConfiguration = SecurityConfiguration.of(
            objectMapper.createObjectNode().put("password", "aaaaaa"),
            "some_user",
            configuration
        );
        final var result = internalUsersApiActionEndpointValidator.onConfigChange(securityConfiguration);
        assertEquals(RestStatus.OK, result.status());
        assertFalse(securityConfiguration.requestContent().has("password"));
        assertTrue(securityConfiguration.requestContent().has("hash"));
        assertTrue(passwordHasher.check("aaaaaa".toCharArray(), securityConfiguration.requestContent().get("hash").asText()));
    }

    @Test
    public void withAuthTokenPath() throws Exception {
        final var internalUsersApiAction = createInternalUsersApiAction();
        var result = internalUsersApiAction.withAuthTokenPath(
            FakeRestRequest.builder()
                .withMethod(RestRequest.Method.POST)
                .withPath("_plugins/_security/api/internalusers/aaaa")
                .withParams(Map.of("name", "aaaa"))
                .build()
        );
        assertFalse(result.isValid());
        assertEquals(RestStatus.NOT_IMPLEMENTED, result.status());

        result = internalUsersApiAction.withAuthTokenPath(
            FakeRestRequest.builder()
                .withMethod(RestRequest.Method.POST)
                .withPath("_plugins/_security/api/internalusers/aaaa/authtoken")
                .withParams(Map.of("name", "aaaa"))
                .build()
        );
        assertTrue(result.isValid());
        assertEquals(RestStatus.OK, result.status());
    }

    @Test
    public void validateAndUpdatePassword() throws Exception {
        final var internalUsersApiAction = createInternalUsersApiAction();

        var result = internalUsersApiAction.validateAndUpdatePassword(
            SecurityConfiguration.of(objectMapper.createObjectNode().set("hash", objectMapper.nullNode()), "aaaa", configuration)
        );
        assertTrue(result.isValid());

        when(configuration.exists("aaaa")).thenReturn(true);
        Mockito.<Object>when(configuration.getCEntry("aaaa")).thenReturn(new InternalUserV7());
        result = internalUsersApiAction.validateAndUpdatePassword(
            SecurityConfiguration.of(objectMapper.createObjectNode(), "aaaa", configuration)
        );
        assertFalse(result.isValid());
        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, result.status());
    }

    @Test
    public void validateSecurityRolesWithMutableRolesMappingConfig() throws Exception {
        final var internalUsersApiAction = createInternalUsersApiAction();

        // should ok to set regular role with mutable role mapping
        var userJson = objectMapper.createObjectNode().set("opendistro_security_roles", objectMapper.createArrayNode().add("regular_role"));
        var result = internalUsersApiAction.validateSecurityRoles(SecurityConfiguration.of(userJson, "some_user", configuration));
        assertValidationResultIsValid(result);
        // should be ok to set reserved role with mutable role mapping
        userJson = objectMapper.createObjectNode().set("opendistro_security_roles", objectMapper.createArrayNode().add("kibana_read_only"));
        result = internalUsersApiAction.validateSecurityRoles(SecurityConfiguration.of(userJson, "some_user", configuration));
        assertValidationResultIsValid(result);
        // should be ok to set static role with mutable role mapping
        userJson = objectMapper.createObjectNode().set("opendistro_security_roles", objectMapper.createArrayNode().add("all_access"));
        result = internalUsersApiAction.validateSecurityRoles(SecurityConfiguration.of(userJson, "some_user", configuration));
        assertValidationResultIsValid(result);
        // should not be ok to set hidden role with mutable role mapping
        userJson = objectMapper.createObjectNode().set("opendistro_security_roles", objectMapper.createArrayNode().add("some_hidden_role"));
        result = internalUsersApiAction.validateSecurityRoles(SecurityConfiguration.of(userJson, "some_user", configuration));
        final var errorMessage = xContentToJsonNode(result.errorMessage()).toPrettyString();
        assertThat(errorMessage, allOf(containsString("NOT_FOUND"), containsString("Resource 'some_hidden_role' is not available.")));
    }

    <T> void assertValidationResultIsValid(final ValidationResult<T> result) {
        if (!result.isValid()) {
            fail("Expected valid result, error message: " + xContentToJsonNode(result.errorMessage()).toPrettyString());
        }
    }

    @Test
    public void validateSecurityRolesWithImmutableRolesMappingConfig() throws Exception {
        final var internalUsersApiAction = createInternalUsersApiAction();
        // should not be ok to set role with hidden role mapping
        var userJson = objectMapper.createObjectNode()
            .set("opendistro_security_roles", objectMapper.createArrayNode().add("some_role_with_hidden_mapping"));
        var result = internalUsersApiAction.validateSecurityRoles(SecurityConfiguration.of(userJson, "some_user", configuration));
        assertFalse(result.isValid());
        // should not be ok to set role with reserved role mapping
        userJson = objectMapper.createObjectNode()
            .set("opendistro_security_roles", objectMapper.createArrayNode().add("some_role_with_reserved_mapping"));
        result = internalUsersApiAction.validateSecurityRoles(SecurityConfiguration.of(userJson, "some_user", configuration));
        assertFalse(result.isValid());
        // should not be ok to set role with static role mapping
        userJson = objectMapper.createObjectNode()
            .set("opendistro_security_roles", objectMapper.createArrayNode().add("some_role_with_static_mapping"));
        result = internalUsersApiAction.validateSecurityRoles(SecurityConfiguration.of(userJson, "some_user", configuration));
        assertFalse(result.isValid());
    }

    private InternalUsersApiAction createInternalUsersApiAction() {
        return new InternalUsersApiAction(clusterService, threadPool, userService, securityApiDependencies, new BCryptPasswordHasher());
    }

}
