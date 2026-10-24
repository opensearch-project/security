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

package org.opensearch.security.hasher;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.junit.Test;

import org.opensearch.common.settings.Settings;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

public class PasswordHasherFactoryTests extends LuceneTestCase {

    @Test
    public void shouldIgnoreParametersForUnusedAlgorithms() {
        final Settings settings = Settings.builder()
            .put("plugins.security.password.hashing.algorithm", "bcrypt")
            .put("plugins.security.password.hashing.argon2.type", "unused")
            .put("plugins.security.password.hashing.pbkdf2.function", "unused")
            .build();
        assertThat(PasswordHasherFactory.createPasswordHasher(settings) instanceof BCryptPasswordHasher, is(true));
    }

    @Test
    public void shouldReturnBCryptByDefault() {
        final Settings settings = Settings.EMPTY;
        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        assertThat(passwordHasher instanceof BCryptPasswordHasher, is(true));
    }

    @Test
    public void shouldReturnBCryptWhenBCryptSpecified() {
        final Settings settings = Settings.builder().put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.BCRYPT).build();
        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        assertThat(passwordHasher instanceof BCryptPasswordHasher, is(true));
    }

    @Test
    public void shouldReturnBCryptWhenBCryptWithValidMinorVersionSpecified() {
        final Settings settings = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.BCRYPT)
            .put(PasswordHasherFactory.BCRYPT_MINOR.getKey(), "B")
            .build();
        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        assertThat(passwordHasher instanceof BCryptPasswordHasher, is(true));
    }

    @Test
    public void shouldReturnBCryptWhenBCryptWithValidLogRoundsSpecified() {
        final Settings settings = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.BCRYPT)
            .put(PasswordHasherFactory.BCRYPT_ROUNDS.getKey(), 8)
            .build();
        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        assertThat(passwordHasher instanceof BCryptPasswordHasher, is(true));
    }

    @Test
    public void shouldReturnExceptionWhenInvalidBCryptMinorVersionSpecified() {
        final Settings settings = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.BCRYPT)
            .put(PasswordHasherFactory.BCRYPT_MINOR.getKey(), "X")
            .build();
        assertThrows(IllegalArgumentException.class, () -> { PasswordHasherFactory.createPasswordHasher(settings); });
    }

    @Test
    public void shouldReturnExceptionWhenInvalidBCryptRoundsSpecified() {
        final Settings settings = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.BCRYPT)
            .put(PasswordHasherFactory.BCRYPT_ROUNDS.getKey(), 3)
            .build();
        assertThrows(IllegalArgumentException.class, () -> { PasswordHasherFactory.createPasswordHasher(settings); });

        final Settings settings2 = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.BCRYPT)
            .put(PasswordHasherFactory.BCRYPT_ROUNDS.getKey(), 32)
            .build();
        assertThrows(IllegalArgumentException.class, () -> { PasswordHasherFactory.createPasswordHasher(settings2); });

    }

    @Test
    public void shouldReturnPBKDF2WhenPBKDF2Specified() {
        final Settings settings = Settings.builder().put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2).build();
        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        assertThat(passwordHasher instanceof PBKDF2PasswordHasher, is(true));
    }

    @Test
    public void shouldReturnPBKDF2WhenPBKDF2WithValidFunctionSpecified() {
        final Settings settingsSHA1 = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2)
            .put(PasswordHasherFactory.PBKDF2_FUNCTION.getKey(), "SHA1")
            .build();
        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settingsSHA1);
        assertThat(passwordHasher instanceof PBKDF2PasswordHasher, is(true));

        final Settings settingsSHA224 = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2)
            .put(PasswordHasherFactory.PBKDF2_FUNCTION.getKey(), "SHA224")
            .build();
        passwordHasher = PasswordHasherFactory.createPasswordHasher(settingsSHA224);
        assertThat(passwordHasher instanceof PBKDF2PasswordHasher, is(true));

        final Settings settingsSHA256 = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2)
            .put(PasswordHasherFactory.PBKDF2_FUNCTION.getKey(), "SHA256")
            .build();
        passwordHasher = PasswordHasherFactory.createPasswordHasher(settingsSHA256);
        assertThat(passwordHasher instanceof PBKDF2PasswordHasher, is(true));

        final Settings settingsSHA384 = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2)
            .put(PasswordHasherFactory.PBKDF2_FUNCTION.getKey(), "SHA384")
            .build();
        passwordHasher = PasswordHasherFactory.createPasswordHasher(settingsSHA384);
        assertThat(passwordHasher instanceof PBKDF2PasswordHasher, is(true));

        final Settings settingsSHA512 = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2)
            .put(PasswordHasherFactory.PBKDF2_FUNCTION.getKey(), "SHA512")
            .build();
        passwordHasher = PasswordHasherFactory.createPasswordHasher(settingsSHA512);
        assertThat(passwordHasher instanceof PBKDF2PasswordHasher, is(true));
    }

    @Test
    public void shouldReturnPBKDF2WhenPBKDF2WithValidIterationsSpecified() {
        final Settings settings = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2)
            .put(PasswordHasherFactory.PBKDF2_ITERATIONS.getKey(), 32000)
            .build();

        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        assertThat(passwordHasher instanceof PBKDF2PasswordHasher, is(true));
    }

    @Test
    public void shouldReturnPBKDF2WhenPBKDF2WithValidLengthSpecified() {
        final Settings settings = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2)
            .put(PasswordHasherFactory.PBKDF2_LENGTH.getKey(), 512)
            .build();
        PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        assertThat(passwordHasher instanceof PBKDF2PasswordHasher, is(true));
    }

    @Test
    public void shouldReturnExceptionWhenInvalidPBKDF2FunctionSpecified() {
        final Settings settings = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2)
            .put(PasswordHasherFactory.PBKDF2_FUNCTION.getKey(), "SHA1000")
            .build();
        assertThrows(IllegalArgumentException.class, () -> { PasswordHasherFactory.createPasswordHasher(settings); });
    }

    @Test
    public void shouldReturnExceptionWhenInvalidPBKDF2IterationsSpecified() {
        final Settings settings = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2)
            .put(PasswordHasherFactory.PBKDF2_ITERATIONS.getKey(), -100000)
            .build();
        assertThrows(IllegalArgumentException.class, () -> { PasswordHasherFactory.createPasswordHasher(settings); });
    }

    @Test
    public void shouldReturnExceptionWhenInvalidPBKDF2LengthSpecified() {
        final Settings settings = Settings.builder()
            .put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.PBKDF2)
            .put(PasswordHasherFactory.PBKDF2_LENGTH.getKey(), -100)
            .build();
        assertThrows(IllegalArgumentException.class, () -> { PasswordHasherFactory.createPasswordHasher(settings); });
    }

    @Test
    public void shouldReturnExceptionWhenInvalidHashingAlgorithmSpecified() {
        final Settings settings = Settings.builder().put(PasswordHasherFactory.ALGORITHM.getKey(), "Invalid").build();
        assertThrows(IllegalArgumentException.class, () -> { PasswordHasherFactory.createPasswordHasher(settings); });
    }
}
