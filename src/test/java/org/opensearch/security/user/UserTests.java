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

import org.junit.Test;

import org.opensearch.identity.Subject;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.sameInstance;

public class UserTests {

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
