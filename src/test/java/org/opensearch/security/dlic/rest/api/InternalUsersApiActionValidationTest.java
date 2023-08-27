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

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;
import org.opensearch.security.user.UserService;
import org.opensearch.security.util.FakeRestRequest;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

public class InternalUsersApiActionValidationTest extends AbstractApiActionValidationTest {

    @Mock
    UserService userService;

    @Mock
    SecurityDynamicConfiguration<?> configuration;

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
        assertTrue(OpenBSDBCrypt.checkPassword(securityConfiguration.requestContent().get("hash").asText(), "aaaaaa".toCharArray()));
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

    private InternalUsersApiAction createInternalUsersApiAction() {
        return new InternalUsersApiAction(clusterService, threadPool, userService, securityApiDependencies);
    }

}
