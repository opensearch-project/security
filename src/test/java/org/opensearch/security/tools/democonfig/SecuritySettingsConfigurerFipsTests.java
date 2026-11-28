/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.tools.democonfig;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.dlic.rest.validation.PasswordValidator;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.hasher.PasswordHasherFactory;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.DefaultObjectMapper.yamlMapper;
import static org.opensearch.security.dlic.rest.validation.RequestContentValidator.ValidationError.INVALID_PASSWORD_TOO_SHORT;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.PBKDF2_DEMO_USERS_RESOURCE;
import static org.opensearch.security.tools.democonfig.SecuritySettingsConfigurer.SHIPPED_DEMO_USERS_RESOURCE;
import static org.junit.Assert.assertThrows;

/**
 * FIPS variant of {@link SecuritySettingsConfigurerTests}. The baseline writes its internal_users.yml fixture with the
 * hasher of the current mode, so it never sees the BCrypt hashes the real installer finds. These tests start from the
 * shipped file instead.
 */
public class SecuritySettingsConfigurerFipsTests extends SecuritySettingsConfigurerTests {

    private static final String STRONG_PASSWORD = "myStrongPassword123";

    @Override
    int expectedMinimumPasswordLength() {
        return PasswordValidator.FIPS_MIN_PASSWORD_LENGTH;
    }

    @Override
    Map<String, Object> expectedModeSpecificSecuritySettings() {
        return Map.of(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2);
    }

    @Test
    public void testShippedDemoUsersAreReplacedWithPbkdf2() throws Exception {
        writeShippedDemoUsers();
        setEnv(adminPasswordKey, STRONG_PASSWORD);

        securitySettingsConfigurer.configureSecuritySettings();

        verifyStdOutContainsString("FIPS mode: replaced the BCrypt demo users in internal_users.yml with PBKDF2 hashes.");
        verifyStdOutContainsString("Admin password set successfully.");

        final JsonNode installedUsers = yamlMapper().readTree(internalUsersFile().toFile());
        final JsonNode pbkdf2Users = readDemoConfigResource(PBKDF2_DEMO_USERS_RESOURCE);
        final String adminHash = installedUsers.get("admin").get("hash").asString();
        assertThat(pbkdf2Hasher().check(STRONG_PASSWORD.toCharArray(), adminHash), is(true));
        for (String user : new String[] { "anomalyadmin", "kibanaserver", "kibanaro", "logstash", "readall", "snapshotrestore" }) {
            assertThat(user, installedUsers.get(user), equalTo(pbkdf2Users.get(user)));
        }

        final JsonNode openSearchYml = yamlMapper().readTree(new File(installer.OPENSEARCH_CONF_FILE));
        assertThat(openSearchYml.get(PasswordHasherFactory.ALGORITHM.getKey()).asString(), equalTo(PasswordHasherFactory.PBKDF2));
    }

    @Test
    public void testCustomizedInternalUsersAreKept() throws Exception {
        writeShippedDemoUsers();
        final String customized = Files.readString(internalUsersFile(), StandardCharsets.UTF_8)
            + "\noperator:\n  hash: \"custom\"\n  description: \"Added by the operator\"\n";
        Files.writeString(internalUsersFile(), customized, StandardCharsets.UTF_8);

        securitySettingsConfigurer.replaceShippedDemoUsersWithPbkdf2();

        verifyStdOutContainsString("FIPS mode: internal_users.yml differs from the shipped demo users, so it is kept as it is.");
        assertThat(Files.readString(internalUsersFile(), StandardCharsets.UTF_8), equalTo(customized));
    }

    /**
     * A customized file keeps its BCrypt hashes under FIPS. The PBKDF2 hasher rejects such a hash, so the installer leaves the
     * admin password alone instead of failing.
     */
    @Test
    public void testUpdateAdminPasswordKeepsAdminHashOfAnotherAlgorithm() throws Exception {
        writeShippedDemoUsers();
        final String customized = Files.readString(internalUsersFile(), StandardCharsets.UTF_8)
            + "\noperator:\n  hash: \"custom\"\n  description: \"Added by the operator\"\n";
        Files.writeString(internalUsersFile(), customized, StandardCharsets.UTF_8);
        setEnv(adminPasswordKey, STRONG_PASSWORD);

        securitySettingsConfigurer.updateAdminPassword();

        verifyStdOutContainsString("The admin hash in internal_users.yml was not created with the configured password hashing algorithm");
        verifyStdOutContainsString("Admin password seems to be custom configured. Skipping update to admin password.");
        assertThat(Files.readString(internalUsersFile(), StandardCharsets.UTF_8), equalTo(customized));
    }

    /**
     * A second run after an aborted one finds the PBKDF2 demo users already in place and leaves them alone.
     */
    @Test
    public void testPbkdf2DemoUsersAreKeptSilentlyOnSecondRun() throws Exception {
        try (InputStream pbkdf2 = SecuritySettingsConfigurer.class.getResourceAsStream(PBKDF2_DEMO_USERS_RESOURCE)) {
            Files.copy(pbkdf2, internalUsersFile(), StandardCopyOption.REPLACE_EXISTING);
        }
        final String before = Files.readString(internalUsersFile(), StandardCharsets.UTF_8);

        securitySettingsConfigurer.replaceShippedDemoUsersWithPbkdf2();

        verifyStdOutDoesNotContainString("FIPS mode:");
        assertThat(Files.readString(internalUsersFile(), StandardCharsets.UTF_8), equalTo(before));
    }

    /**
     * Strong passwords below the FIPS floor pass the demo rules outside FIPS but cannot be hashed with PBKDF2 under FIPS.
     */
    @Test
    public void testUpdateAdminPasswordRejectsPasswordBelowFipsMinimum() throws Exception {
        final String thirteenCharacters = "Xk9#mQ2$vL7&p";
        setEnv(adminPasswordKey, thirteenCharacters);
        installer.setExitHandler(status -> { throw new TestExitException(status); });

        final TestExitException exit = assertThrows(TestExitException.class, () -> securitySettingsConfigurer.updateAdminPassword());

        assertThat(exit.getStatus(), equalTo(-1));
        verifyStdOutContainsString(INVALID_PASSWORD_TOO_SHORT.message());
        verifyStdOutContainsString("minimum " + PasswordValidator.FIPS_MIN_PASSWORD_LENGTH + " character password");
    }

    private static Path internalUsersFile() {
        return Path.of(installer.OPENSEARCH_CONF_DIR, "opensearch-security", "internal_users.yml");
    }

    private static void writeShippedDemoUsers() throws IOException {
        try (InputStream shipped = SecuritySettingsConfigurer.class.getResourceAsStream(SHIPPED_DEMO_USERS_RESOURCE)) {
            Files.copy(shipped, internalUsersFile(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static PasswordHasher pbkdf2Hasher() {
        return PasswordHasherFactory.createPasswordHasher(
            Settings.builder().put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2).build()
        );
    }
}
