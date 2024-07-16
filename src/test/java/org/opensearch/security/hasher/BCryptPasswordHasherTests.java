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
import static org.hamcrest.Matchers.startsWith;

public class BCryptPasswordHasherTests extends AbstractPasswordHasherTests {

    @Before
    public void setup() {
        passwordHasher = new BCryptPasswordHasher(
            ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_MINOR_DEFAULT,
            ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS_DEFAULT
        );
    }

    /**
     * Ensures that the hashes that were previously created by OpenBSDBCrypt are still valid
     */
    @Test
    public void shouldBeBackwardsCompatible() {
        String legacyHash = "$2y$12$gdh2ecVBQmwpmcAeyReicuNtXyR6GMWSfXHxtcBBqFeFz2VQ8kDZe";
        assertThat(passwordHasher.check(password.toCharArray(), legacyHash), is(true));
        assertThat(passwordHasher.check(wrongPassword.toCharArray(), legacyHash), is(false));
    }

    @Test
    public void shouldGenerateAValidHashForParameters() {
        PasswordHasher hasher = new BCryptPasswordHasher("A", 8);
        String hash = hasher.hash(password.toCharArray());
        assertThat(hash, startsWith("$2a$08"));
        assertThat(hasher.check(password.toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));

        hasher = new BCryptPasswordHasher("B", 10);
        hash = hasher.hash(password.toCharArray());
        assertThat(hash, startsWith("$2b$10"));
        assertThat(hasher.check(password.toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));

        hasher = new BCryptPasswordHasher("Y", 13);
        hash = hasher.hash(password.toCharArray());
        assertThat(hash, startsWith("$2y$13"));
        assertThat(hasher.check(password.toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));
    }

}
