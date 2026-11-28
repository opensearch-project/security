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

import org.junit.Test;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

/**
 * FIPS variant of {@link PBKDF2PasswordHasherTests}. Adds the rejection of password material
 * below the FIPS 112-bit floor, which the BC FIPS provider enforces at the KDF level.
 */
public class PBKDF2PasswordHasherFipsTests extends PBKDF2PasswordHasherTests {

    @Override
    protected String getPassword() {
        return "notarealpassword";
    }

    @Test
    public void shouldThrowExceptionForWeakPassword() {
        var hasher = new PBKDF2PasswordHasher("SHA512", 10000, 512);
        assertThrows(FipsUnapprovedOperationError.class, () -> hasher.hash("test".toCharArray()));
    }

    /**
     * A login attempt with a password below the FIPS floor fails like a wrong password instead of throwing the BouncyCastle
     * error into the authentication path.
     */
    @Test
    public void shouldFailCheckForPasswordBelowFipsMinimum() {
        final String hash = passwordHasher.hash(getPassword().toCharArray());
        assertThat(passwordHasher.check("short".toCharArray(), hash), is(false));
    }
}
