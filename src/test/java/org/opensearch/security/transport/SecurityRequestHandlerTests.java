/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

import org.junit.Test;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.extensions.ExtensionScopedSettings;
import org.opensearch.extensions.ExtensionsSettings;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class SecurityRequestHandlerTests {

    private static ExtensionsSettings.Extension prepareExtension(String... dn) {
        Setting<List<String>> distinguishedNames = Setting.listSetting(
            "distinguishedNames",
            List.of(),
            Function.identity(),
            Setting.Property.ExtensionScope
        );

        ExtensionScopedSettings scopedSettings = new ExtensionScopedSettings(Set.of(distinguishedNames));
        Map<String, ?> additionalSettingsMap = Map.of("distinguishedNames", dn);

        Settings.Builder output = Settings.builder();
        output.loadFromMap(additionalSettingsMap);
        scopedSettings.applySettings(output.build());

        return new ExtensionsSettings.Extension(
            "name",
            "uniqueId",
            "hostAddress",
            "port",
            "version",
            "opensearchVersion",
            "minimumCompatibleVersion",
            List.of(),
            scopedSettings
        );
    }

    @Test
    public void testShouldAllowExtensionRequest() {
        String principal = "CN=transport-0.example.com, OU=SSL, O=Test, L=Test, C=DE";

        ExtensionsSettings.Extension extension = prepareExtension(
            "CN=transport-1.example.com, OU=SSL, O=Test, L=Test, C=DE",
            "CN=transport-0.example.com, OU=SSL, O=Test, L=Test, C=DE"
        );

        assertTrue(SecurityRequestHandler.isExtensionAllowed(extension, principal));

        extension = prepareExtension("CN=NonPass", "CN=*0.example.com, OU=SSL, O=Test, L=Test, C=*", "CN=NonPass");
        assertTrue(SecurityRequestHandler.isExtensionAllowed(extension, principal));

        extension = prepareExtension("CN=*");
        assertTrue(SecurityRequestHandler.isExtensionAllowed(extension, principal));

        extension = prepareExtension();
        assertTrue(SecurityRequestHandler.isExtensionAllowed(extension, principal));
    }

    @Test
    public void testShouldNotAllowExtensionRequest() {
        String principal = "CN=transport-0.example.com, OU=SSL, O=Test, L=Test, C=DE";
        ExtensionsSettings.Extension extension = prepareExtension("CN=*0.example.com, OU=SSL, O=false, L=Test, C=*");

        assertFalse(SecurityRequestHandler.isExtensionAllowed(extension, principal));
    }
}
