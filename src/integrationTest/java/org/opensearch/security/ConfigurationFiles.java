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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
            Path tempDirectory = Files.createTempDirectory("test-security-config-");
            String[] configurationFiles = {
                "config.yml",
                "action_groups.yml",
                "internal_users.yml",
                "nodes_dn.yml",
                "roles.yml",
                "roles_mapping.yml",
                "security_tenants.yml",
                "tenants.yml",
                "whitelist.yml" };
            for (String fileName : configurationFiles) {
                Path configFileDestination = tempDirectory.resolve(fileName);
                copyResourceToFile(fileName, configFileDestination.toFile());
            }
            return tempDirectory.toAbsolutePath();
        } catch (IOException ex) {
            throw new RuntimeException("Cannot create directory with security plugin configuration.", ex);
        }
    }

    public static void writeToConfig(final CType cType, final Path configFolder, final String content) throws IOException {
        if (Strings.isNullOrEmpty(content)) return;
        final Path configFile = resolveFileFor(cType, configFolder);
        try (final var out = Files.newOutputStream(configFile, StandardOpenOption.APPEND)) {
            out.write(content.getBytes(StandardCharsets.UTF_8));
            out.flush();
        }
    }

    private static Path resolveFileFor(final CType cType, final Path configFolder) {
        switch (cType) {
            case ACTIONGROUPS:
                return configFolder.resolve("action_groups.yml");
            case INTERNALUSERS:
                return configFolder.resolve("internal_users.yml");
            case ROLES:
                return configFolder.resolve("roles.yml");
            case ROLESMAPPING:
                return configFolder.resolve("roles_mapping.yml");
            default:
                throw new IllegalArgumentException("Unsupported configuration type: " + cType);
        }
    }

    public static void createRoleMappingFile(File destination) {
        String resource = "roles_mapping.yml";
        copyResourceToFile(resource, destination);
    }

    private static void copyResourceToFile(String resource, File destination) {
        try (InputStream input = ConfigurationFiles.class.getClassLoader().getResourceAsStream(resource)) {
            Objects.requireNonNull(input, "Cannot find source resource " + resource);
            try (OutputStream output = new FileOutputStream(destination)) {
                input.transferTo(output);
            }
        } catch (IOException e) {
            throw new RuntimeException("Cannot create file with security plugin configuration", e);
        }
    }
}
