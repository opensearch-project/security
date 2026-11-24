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

import org.opensearch.common.settings.Settings;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

public class PBKDF2PasswordHasherTests extends AbstractPasswordHasherTests {

    @Before
    public void setup() {
        passwordHasher = new PBKDF2PasswordHasher(
            PasswordHasherFactory.PBKDF2_FUNCTION.getDefault(Settings.EMPTY),
            PasswordHasherFactory.PBKDF2_ITERATIONS.getDefault(Settings.EMPTY),
            PasswordHasherFactory.PBKDF2_LENGTH.getDefault(Settings.EMPTY)
        );
    }

    @Test
    public void shouldGenerateValidHashesFromParameters() {
        PasswordHasher hasher = new PBKDF2PasswordHasher("SHA1", 150000, 128);
        String hash = hasher.hash(getPassword().toCharArray());
        assertThat(hasher.check(getPassword().toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));

        hasher = new PBKDF2PasswordHasher("SHA224", 100000, 224);
        hash = hasher.hash(getPassword().toCharArray());
        assertThat(hasher.check(getPassword().toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));

        hasher = new PBKDF2PasswordHasher("SHA256", 75000, 256);
        hash = hasher.hash(getPassword().toCharArray());
        assertThat(hasher.check(getPassword().toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));

        hasher = new PBKDF2PasswordHasher("SHA384", 50000, 384);
        hash = hasher.hash(getPassword().toCharArray());
        assertThat(hasher.check(getPassword().toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));

        hasher = new PBKDF2PasswordHasher("SHA512", 10000, 512);
        hash = hasher.hash(getPassword().toCharArray());
        assertThat(hasher.check(getPassword().toCharArray(), hash), is(true));
        assertThat(hasher.check(wrongPassword.toCharArray(), hash), is(false));
    }

    /**
     * Only the FIPS rejection of short passwords counts as a failed check; a hash of another algorithm is a configuration
     * error and stays visible to the caller.
     */
    @Test
    public void shouldRejectHashOfAnotherAlgorithm() {
        final String bcryptHash = "$2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG";
        assertThrows(IllegalArgumentException.class, () -> passwordHasher.check(getPassword().toCharArray(), bcryptHash));
    }
}
