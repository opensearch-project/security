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

import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;

import com.password4j.types.Argon2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class Argon2PasswordHasherTests extends AbstractPasswordHasherTests {

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

    @Test
    public void parseType() {
        assertEquals(Argon2.ID, Argon2PasswordHasher.parseType("argon2id"));
        assertEquals(Argon2.I, Argon2PasswordHasher.parseType("argon2i"));
        assertEquals(Argon2.D, Argon2PasswordHasher.parseType("argon2d"));
    }

    @Test
    public void parseType_invalid() {
        assertThrows(IllegalArgumentException.class, () -> Argon2PasswordHasher.parseType("invalid"));
        assertThrows(IllegalArgumentException.class, () -> Argon2PasswordHasher.parseType(null));
    }
}
