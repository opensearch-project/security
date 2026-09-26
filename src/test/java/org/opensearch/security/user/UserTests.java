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

package org.opensearch.security.user;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import org.opensearch.identity.Subject;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

public class UserTests {

    @Test
    public void testRequestTenantContextPreservesAuthenticationMethod() {
        for (String authenticationMethod : List.of("basic", "onbehalfof_jwt", "apitoken")) {
            User original = new User("test-user").withRoles("backend-role")
                .withSecurityRoles(List.of("security-role"))
                .withAttributes(Map.of("attribute", "value"));
            original.setAuthenticatedBy(authenticationMethod);

            User userWithTenantContext = original.withRequestedTenant("tenant-one");
            assertThat(original.getRequestedTenant(), nullValue());
            for (User user : List.of(
                userWithTenantContext,
                userWithTenantContext.withRequestedTenant("tenant-two"),
                userWithTenantContext.withRequestedTenant(null)
            )) {
                assertThat(user.getAuthenticatedBy(), equalTo(authenticationMethod));
                assertThat(user.getName(), equalTo(original.getName()));
                assertThat(user.getRoles(), equalTo(original.getRoles()));
                assertThat(user.getSecurityRoles(), equalTo(original.getSecurityRoles()));
                assertThat(user.getCustomAttributesMap(), equalTo(original.getCustomAttributesMap()));
                assertThat(user.isInjected(), equalTo(original.isInjected()));
            }
            assertThat(userWithTenantContext.getRequestedTenant(), equalTo("tenant-one"));
            assertThat(userWithTenantContext.withRequestedTenant("tenant-one"), sameInstance(userWithTenantContext));
            assertThat(original.getAuthenticatedBy(), equalTo(authenticationMethod));
        }
    }

    @Test
    public void testRequestTenantContextPreservesUnsetAuthenticationMethod() {
        assertThat(new User("test-user").withRequestedTenant("tenant").getAuthenticatedBy(), nullValue());
    }

    @Test
    public void testUserIsSubjectAndPrincipal() {
        User user = new User("test-user");
        Subject subject = user;

        assertThat(subject.getPrincipal(), sameInstance(user));
        assertThat(subject.getPrincipal().getName(), equalTo(user.getName()));
    }

    @Test
    public void testUserCanBeSerializedWithJackson3() throws Exception {
        User user = new User("test-user");
        ObjectMapper objectMapper = new ObjectMapper();

        String userContext = objectMapper.writeValueAsString(user);
        JsonNode serializedUser = objectMapper.readTree(userContext);

        assertThat(serializedUser.get("name").asText(), equalTo(user.getName()));
        assertThat(serializedUser.has("principal"), equalTo(false));
    }
}
