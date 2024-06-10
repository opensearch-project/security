/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;

import org.opensearch.core.common.Strings;
import org.opensearch.security.securityconf.impl.CType;

public class ConfigurationFiles {

    public static Path createConfigurationDirectory() {
        try {
            Path tempDirectory = Files.createTempDirectory("test-security-config");
            String[] configurationFiles = {
                CType.ACTIONGROUPS.configFileName(),
                CType.CONFIG.configFileName(),
                CType.INTERNALUSERS.configFileName(),
                CType.NODESDN.configFileName(),
                CType.ROLES.configFileName(),
                CType.ROLESMAPPING.configFileName(),
                "security_tenants.yml",
                CType.TENANTS.configFileName(),
                CType.WHITELIST.configFileName() };
            for (String fileName : configurationFiles) {
                copyResourceToFile(fileName, tempDirectory.resolve(fileName));
            }
            return tempDirectory.toAbsolutePath();
        } catch (IOException ex) {
            throw new RuntimeException("Cannot create directory with security plugin configuration.", ex);
        }
    }

    public static void writeToConfig(final CType cType, final Path configFolder, final String content) throws IOException {
        if (Strings.isNullOrEmpty(content)) return;
        try (final var out = Files.newOutputStream(cType.configFile(configFolder), StandardOpenOption.APPEND)) {
            out.write(content.getBytes(StandardCharsets.UTF_8));
            out.flush();
        }
    }

    public static void copyResourceToFile(String resource, Path destination) {
        try (InputStream input = ConfigurationFiles.class.getClassLoader().getResourceAsStream(resource)) {
            Objects.requireNonNull(input, "Cannot find source resource " + resource);
            try (final var output = Files.newOutputStream(destination)) {
                input.transferTo(output);
            }
        } catch (IOException e) {
            throw new RuntimeException("Cannot create file with security plugin configuration", e);
        }
    }
}
