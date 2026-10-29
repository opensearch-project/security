/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.http.saml;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.BeforeClass;
import org.junit.Test;

import com.onelogin.saml2.util.Util;
import org.opensaml.messaging.decoder.MessageDecodingException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class MockSamlIdpServerTest {
    @BeforeClass
    public static void initializeOpenSaml() {
        HTTPSamlAuthenticator.ensureOpenSamlInitialization();
    }

    @Test
    public void decodesUnchunkedRedirectMessage() throws Exception {
        String message = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
            + " ID=\"_1234567890abcdef\" Version=\"2.0\" IssueInstant=\"2026-10-24T00:00:00Z\""
            + " Destination=\"https://idp.example.org/sso\"/>";
        String encoded = Util.deflatedBase64encoded(message);
        assertTrue(encoded.length() > 76);
        assertFalse(encoded.contains("\n"));
        try (var decoded = new MockSamlIdpServer.RedirectDecoder().decodeMessage(encoded)) {
            assertEquals(message, new String(decoded.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    @Test
    public void rejectsInvalidBase64() {
        assertThrows(MessageDecodingException.class, () -> new MockSamlIdpServer.RedirectDecoder().decodeMessage("not!base64"));
    }

    @Test
    public void rejectsInvalidDeflateData() throws Exception {
        String encoded = Base64.getEncoder().encodeToString("not deflated XML".getBytes(StandardCharsets.UTF_8));
        try (var decoded = new MockSamlIdpServer.RedirectDecoder().decodeMessage(encoded)) {
            assertThrows(IOException.class, decoded::readAllBytes);
        }
    }
}
