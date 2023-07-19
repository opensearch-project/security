/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

import org.junit.Test;
import org.opensearch.extensions.ExtensionScopedSettings;
import org.opensearch.extensions.ExtensionsSettings;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class SecurityRequestHandlerTests {

    private SecurityRequestHandler securityRequestHandler = new SecurityRequestHandler(
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null
    );

    @Test
    public void testShouldAllowExtensionRequest() {
        String principal = "CN=transport-0.example.com, OU=SSL, O=Test, L=Test, C=DE";
        ExtensionsSettings.Extension extension = new ExtensionsSettings.Extension(
            "name",
            "uniqueId",
            "hostAddress",
            "port",
            "version",
            "opensearchVersion",
            "minimumCompatibleVersion",
            List.of("CN=transport-1.example.com, OU=SSL, O=Test, L=Test, C=DE", "CN=transport-0.example.com, OU=SSL, O=Test, L=Test, C=DE"),
            List.of(),
            new ExtensionScopedSettings(Set.of())
        );

        assertTrue(securityRequestHandler.isExtensionAllowed(extension.getDistinguishedNames(), principal));

        extension = new ExtensionsSettings.Extension(
            "name",
            "uniqueId",
            "hostAddress",
            "port",
            "version",
            "opensearchVersion",
            "minimumCompatibleVersion",
            List.of("CN=*0.example.com, OU=SSL, O=Test, L=Test, C=*"),
            List.of(),
            new ExtensionScopedSettings(Set.of())
        );
        assertTrue(securityRequestHandler.isExtensionAllowed(extension.getDistinguishedNames(), principal));

        extension = new ExtensionsSettings.Extension(
            "name",
            "uniqueId",
            "hostAddress",
            "port",
            "version",
            "opensearchVersion",
            "minimumCompatibleVersion",
            List.of("CN=*"),
            List.of(),
            new ExtensionScopedSettings(Set.of())
        );
        assertTrue(securityRequestHandler.isExtensionAllowed(extension.getDistinguishedNames(), principal));

        extension = new ExtensionsSettings.Extension(
            "name",
            "uniqueId",
            "hostAddress",
            "port",
            "version",
            "opensearchVersion",
            "minimumCompatibleVersion",
            null,
            List.of(),
            new ExtensionScopedSettings(Set.of())
        );
        assertTrue(securityRequestHandler.isExtensionAllowed(extension.getDistinguishedNames(), principal));

        extension = new ExtensionsSettings.Extension(
            "name",
            "uniqueId",
            "hostAddress",
            "port",
            "version",
            "opensearchVersion",
            "minimumCompatibleVersion",
            null,
            null,
            new ExtensionScopedSettings(Set.of())
        );
        assertTrue(securityRequestHandler.isExtensionAllowed(extension.getDistinguishedNames(), principal));
    }

    @Test
    public void testShouldNotAllowExtensionRequest() {
        String principal = "CN=transport-0.example.com, OU=SSL, O=Test, L=Test, C=DE";
        ExtensionsSettings.Extension extension = new ExtensionsSettings.Extension(
            "name",
            "uniqueId",
            "hostAddress",
            "port",
            "version",
            "opensearchVersion",
            "minimumCompatibleVersion",
            List.of("CN=*0.example.com, OU=SSL, O=false, L=Test, C=*"),
            List.of(),
            new ExtensionScopedSettings(Set.of())
        );
        assertFalse(securityRequestHandler.isExtensionAllowed(extension.getDistinguishedNames(), principal));
    }
}
