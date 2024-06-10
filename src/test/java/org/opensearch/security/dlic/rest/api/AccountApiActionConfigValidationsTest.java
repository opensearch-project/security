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

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Test;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;

import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class AccountApiActionConfigValidationsTest extends AbstractApiActionValidationTest {

    @Test
    public void verifyValidCurrentPassword() {
        final var accountApiAction = new AccountApiAction(clusterService, threadPool, securityApiDependencies, passwordHasher);

        final var u = createExistingUser();

        var result = accountApiAction.validCurrentPassword(SecurityConfiguration.of(requestContent(), "u", configuration));
        assertThat(result.isValid(), is(false));
        assertThat(RestStatus.BAD_REQUEST, is(result.status()));

        u.setHash(passwordHasher.hash("aaaa".toCharArray()));
        result = accountApiAction.validCurrentPassword(SecurityConfiguration.of(requestContent(), "u", configuration));
        assertThat(result.isValid(), is(true));
    }

    @Test
    public void updatePassword() {
        final var accountApiAction = new AccountApiAction(clusterService, threadPool, securityApiDependencies, passwordHasher);

        final var requestContent = requestContent();
        requestContent.remove("password");
        final var u = createExistingUser();
        u.setHash(null);

        var result = accountApiAction.updatePassword(SecurityConfiguration.of(requestContent, "u", configuration));
        assertThat(result.isValid(), is(false));
        assertThat(RestStatus.BAD_REQUEST, is(result.status()));

        requestContent.put("password", "cccccc");
        result = accountApiAction.updatePassword(SecurityConfiguration.of(requestContent, "u", configuration));
        assertThat(result.isValid(), is(true));
        assertThat(passwordHasher.check("cccccc".toCharArray(), u.getHash()), is(true));

        requestContent.remove("password");
        requestContent.put("hash", passwordHasher.hash("dddddd".toCharArray()));
        result = accountApiAction.updatePassword(SecurityConfiguration.of(requestContent, "u", configuration));
        assertThat(result.isValid(), is(true));
        assertThat(passwordHasher.check("dddddd".toCharArray(), u.getHash()), is(true));
    }

    private ObjectNode requestContent() {
        return objectMapper.createObjectNode().put("current_password", "aaaa").put("password", "bbbb");
    }

    private InternalUserV7 createExistingUser() {
        final var u = new InternalUserV7();
        u.setHash(passwordHasher.hash("sssss".toCharArray()));
        Mockito.<Object>when(configuration.getCEntry("u")).thenReturn(u);
        return u;
    }

}
