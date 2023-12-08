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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

class ConfigurationFiles {

    public static void createRoleMappingFile(File destination) {
        String resource = "roles_mapping.yml";
        copyResourceToFile(resource, destination);
    }

    public static Path createConfigurationDirectory() {
        try {
            Path tempDirectory = Files.createTempDirectory("test-security-config");
            String[] configurationFiles = {
                "config.yml",
                "action_groups.yml",
                "config.yml",
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
