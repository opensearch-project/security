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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class PBKDF2PasswordHasherTests extends AbstractPasswordHasherTests {

    @Before
    public void setup() {
        passwordHasher = new PBKDF2PasswordHasher(
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH_DEFAULT
        );
    }

    @Test
    public void shouldGenerateValidHashesFromParameters() {
        PasswordHasher hasher = new PBKDF2PasswordHasher("SHA1", 150000, 128);
        String hash = hasher.hash(password.toCharArray());
        assertThat(hasher.check(password.toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));

        hasher = new PBKDF2PasswordHasher("SHA224", 100000, 224);
        hash = hasher.hash(password.toCharArray());
        assertThat(hasher.check(password.toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));

        hasher = new PBKDF2PasswordHasher("SHA256", 75000, 256);
        hash = hasher.hash(password.toCharArray());
        assertThat(hasher.check(password.toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));

        hasher = new PBKDF2PasswordHasher("SHA384", 50000, 384);
        hash = hasher.hash(password.toCharArray());
        assertThat(hasher.check(password.toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));

        hasher = new PBKDF2PasswordHasher("SHA512", 10000, 512);
        hash = hasher.hash(password.toCharArray());
        assertThat(hasher.check(password.toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));
    }
}
