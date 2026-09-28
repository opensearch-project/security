/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThrows;

public class OpenSearchSecurityPluginFIPSValidationTest {

    @Test
    public void testFipsModeWithDefaultAlgorithmThrows() {
        // Default algorithm is bcrypt, which is not FIPS-compliant
        Settings settings = Settings.builder().build();

        IllegalStateException ex = assertThrows(
            IllegalStateException.class,
            () -> OpenSearchSecurityPlugin.validateFipsMode("true", settings)
        );
        assertThat(ex.getMessage(), containsString("FIPS mode is enabled"));
        assertThat(ex.getMessage(), containsString("Only PBKDF2 is allowed in FIPS mode"));
        assertThat(ex.getMessage(), containsString("changing the hashing algorithm requires all existing passwords to be rehashed"));
    }

    @Test
    public void testFipsModeWithBcryptThrows() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, "bcrypt").build();

        IllegalStateException ex = assertThrows(
            IllegalStateException.class,
            () -> OpenSearchSecurityPlugin.validateFipsMode("true", settings)
        );
        assertThat(ex.getMessage(), containsString("bcrypt"));
        assertThat(ex.getMessage(), containsString("FIPS mode is enabled"));
    }

    @Test
    public void testFipsModeWithArgon2Throws() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, "argon2").build();

        IllegalStateException ex = assertThrows(
            IllegalStateException.class,
            () -> OpenSearchSecurityPlugin.validateFipsMode("true", settings)
        );
        assertThat(ex.getMessage(), containsString("argon2"));
    }

    @Test
    public void testFipsModeWithPbkdf2Succeeds() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, "pbkdf2").build();

        // Should not throw
        OpenSearchSecurityPlugin.validateFipsMode("true", settings);
    }

    @Test
    public void testFipsModeWithPbkdf2UpperCaseSucceeds() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, "PBKDF2").build();

        // Should not throw
        OpenSearchSecurityPlugin.validateFipsMode("true", settings);
    }

    @Test
    public void testFipsModeDisabledAllowsAnyAlgorithm() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, "bcrypt").build();

        // Should not throw when FIPS mode is not enabled
        OpenSearchSecurityPlugin.validateFipsMode("false", settings);
    }

    @Test
    public void testFipsModeNullEnvAllowsAnyAlgorithm() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, "bcrypt").build();

        // Should not throw when env var is null
        OpenSearchSecurityPlugin.validateFipsMode(null, settings);
    }
}
