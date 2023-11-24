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
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;

import org.mockito.Mockito;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AccountApiActionConfigValidationsTest extends AbstractApiActionValidationTest {

    @Test
    public void verifyValidCurrentPassword() {
        final var accountApiAction = new AccountApiAction(clusterService, threadPool, securityApiDependencies);

        final var u = createExistingUser();

        var result = accountApiAction.validCurrentPassword(SecurityConfiguration.of(requestContent(), "u", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());

        u.setHash(Utils.hash("aaaa".toCharArray()));
        result = accountApiAction.validCurrentPassword(SecurityConfiguration.of(requestContent(), "u", configuration));
        assertTrue(result.isValid());
    }

    @Test
    public void updatePassword() {
        final var accountApiAction = new AccountApiAction(clusterService, threadPool, securityApiDependencies);

        final var requestContent = requestContent();
        requestContent.remove("password");
        final var u = createExistingUser();
        u.setHash(null);

        var result = accountApiAction.updatePassword(SecurityConfiguration.of(requestContent, "u", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());

        requestContent.put("password", "cccccc");
        result = accountApiAction.updatePassword(SecurityConfiguration.of(requestContent, "u", configuration));
        assertTrue(result.isValid());
        assertTrue(OpenBSDBCrypt.checkPassword(u.getHash(), "cccccc".toCharArray()));

        requestContent.remove("password");
        requestContent.put("hash", Utils.hash("dddddd".toCharArray()));
        result = accountApiAction.updatePassword(SecurityConfiguration.of(requestContent, "u", configuration));
        assertTrue(result.isValid());
        assertTrue(OpenBSDBCrypt.checkPassword(u.getHash(), "dddddd".toCharArray()));
    }

    private ObjectNode requestContent() {
        return objectMapper.createObjectNode().put("current_password", "aaaa").put("password", "bbbb");
    }

    private InternalUserV7 createExistingUser() {
        final var u = new InternalUserV7();
        u.setHash(Utils.hash("sssss".toCharArray()));
        Mockito.<Object>when(configuration.getCEntry("u")).thenReturn(u);
        return u;
    }

}
