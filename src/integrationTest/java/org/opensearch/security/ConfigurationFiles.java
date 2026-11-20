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
import java.util.Objects;

import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.test.framework.TestSecurityConfig;

public class ConfigurationFiles {

    public static Path createConfigurationDirectory() {
        try {
            Path tempDirectory = Files.createTempDirectory("test-security-config");
            String[] configurationFiles = {
                CType.ACTIONGROUPS.configFileName(),
                CType.CONFIG.configFileName(),
                CType.NODESDN.configFileName(),
                CType.ROLES.configFileName(),
                CType.ROLESMAPPING.configFileName(),
                "security_tenants.yml",
                CType.TENANTS.configFileName() };
            for (String fileName : configurationFiles) {
                copyResourceToFile(fileName, tempDirectory.resolve(fileName));
            }
            writeInternalUsersFile(tempDirectory.resolve(CType.INTERNALUSERS.configFileName()));
            return tempDirectory.toAbsolutePath();
        } catch (IOException ex) {
            throw new RuntimeException("Cannot create directory with security plugin configuration.", ex);
        }
    }

    // Generates internal_users.yml with a hash derived from DEFAULT_TEST_PASSWORD so the
    // admin user can authenticate in both FIPS and non-FIPS mode without a hardcoded BCrypt hash.
    private static void writeInternalUsersFile(Path destination) throws IOException {
        String hash = TestSecurityConfig.hashPassword(TestSecurityConfig.DEFAULT_TEST_PASSWORD);
        String content = """
            ---
            _meta:
              type: "internalusers"
              config_version: 2
            new-user:
              hash: "%s"
            limited-user:
              hash: "%s"
              opendistro_security_roles:
              - "user_limited-user__limited-role"
            admin:
              hash: "%s"
              opendistro_security_roles:
              - "user_admin__all_access"
            """.formatted(hash, hash, hash);
        Files.writeString(destination, content, StandardCharsets.UTF_8);
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
