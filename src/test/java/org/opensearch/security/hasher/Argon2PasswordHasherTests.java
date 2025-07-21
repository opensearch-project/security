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

import java.util.Arrays;
import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@RunWith(Parameterized.class)
public class Argon2PasswordHasherTests extends AbstractPasswordHasherTests {

    private final int memory;
    private final int iterations;
    private final int parallelism;
    private final int length;
    private final String type;
    private final int version;

    public Argon2PasswordHasherTests(int memory, int iterations, int parallelism, int length, String type, int version) {
        this.memory = memory;
        this.iterations = iterations;
        this.parallelism = parallelism;
        this.length = length;
        this.type = type;
        this.version = version;
    }

    @Before
    public void setup() {
        passwordHasher = new Argon2PasswordHasher(
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_MEMORY_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_PARALLELISM_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_LENGTH_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_TYPE_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_VERSION_DEFAULT
        );
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(
            new Object[][] {
                { 47104, 1, 2, 32, "argon2id", 19 },
                { 19456, 2, 1, 64, "argon2i", 19 },
                { 65536, 1, 1, 128, "argon2d", 19 },
                { 7168, 5, 1, 256, "argon2id", 16 },
                { 9216, 4, 1, 512, "argon2id", 16 },
                { 65536, 3, 1, 1024, "argon2id", 16 },
                { 47104, 3, 2, 128, "argon2id", 19 },
                { 19456, 4, 1, 256, "argon2i", 19 } }
        );
    }

    @Test
    public void shouldGenerateValidHashesFromParameters() {
        PasswordHasher hasher = new Argon2PasswordHasher(memory, iterations, parallelism, length, type, version);
        String hash = hasher.hash(password.toCharArray());
        assertThat(hasher.check(password.toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));
    }

    @Test
    public void shouldReturnFalseForInvalidHash() {
        PasswordHasher hasher = new Argon2PasswordHasher(memory, iterations, parallelism, length, type, version);
        String invalidHash = "invalid_hash";
        boolean result = hasher.check(password.toCharArray(), invalidHash);
        assertThat("Invalid hash should return false", result, is(false));
    }
}
