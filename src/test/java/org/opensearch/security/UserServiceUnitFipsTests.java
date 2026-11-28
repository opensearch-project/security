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

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.user.UserService;

import static org.junit.Assert.assertTrue;

/**
 * FIPS variant of {@link UserServiceUnitTests}. Generated passwords are drawn from a longer
 * window so that they clear the FIPS 112-bit entropy floor.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class UserServiceUnitFipsTests extends UserServiceUnitTests {

    // FIPS 140-2/3 requires a minimum of 112 bits of entropy for key material.
    private static final double FIPS_MIN_ENTROPY_BITS = 112.0;
    private static final int CHARSET_SIZE = 62; // a-z (26) + A-Z (26) + 0-9 (10)
    private static final int MIN_PASSWORD_LENGTH = 20;

    @Override
    protected int getMinGeneratedPasswordLength() {
        return MIN_PASSWORD_LENGTH;
    }

    @Override
    protected int getMaxGeneratedPasswordLength() {
        return 27;
    }

    @Test
    public void testGeneratedPasswordEntropyMeetsFipsRequirement() {
        double entropyPerChar = Math.log(CHARSET_SIZE) / Math.log(2);
        double minEntropy = entropyPerChar * MIN_PASSWORD_LENGTH;

        assertTrue(
            String.format("Password entropy %.2f bits must be >= %.2f bits (FIPS minimum)", minEntropy, FIPS_MIN_ENTROPY_BITS),
            minEntropy >= FIPS_MIN_ENTROPY_BITS
        );

        char[] password = UserService.generatePassword();
        assertTrue("Generated password must be >= " + MIN_PASSWORD_LENGTH + " chars", password.length >= MIN_PASSWORD_LENGTH);

        double actualEntropy = entropyPerChar * password.length;
        assertTrue(
            String.format("Actual password entropy %.2f bits must be >= %.2f bits", actualEntropy, FIPS_MIN_ENTROPY_BITS),
            actualEntropy >= FIPS_MIN_ENTROPY_BITS
        );
    }
}
