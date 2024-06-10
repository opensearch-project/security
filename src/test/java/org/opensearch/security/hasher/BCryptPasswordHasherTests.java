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

import java.nio.CharBuffer;

import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThrows;

public class BCryptPasswordHasherTests {

    private final PasswordHasher passwordHasher = new BCryptPasswordHasher();

    private final String password = "testPassword";
    private final String wrongPassword = "wrongTestPassword";

    @Test
    public void shouldMatchHashToCorrectPassword() {
        String hashedPassword = passwordHasher.hash(password.toCharArray());
        assertThat(passwordHasher.check(password.toCharArray(), hashedPassword), is(true));
    }

    @Test
    public void shouldNotMatchHashToWrongPassword() {
        String hashedPassword = passwordHasher.hash(password.toCharArray());
        assertThat(passwordHasher.check(wrongPassword.toCharArray(), hashedPassword), is(false));

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
    public void shouldGenerateDifferentHashesForTheSamePassword() {
        String hash1 = passwordHasher.hash(password.toCharArray());
        String hash2 = passwordHasher.hash(password.toCharArray());
        assertThat(hash1, is(not(hash2)));
    }

    @Test
    public void shouldHandleNullPasswordWhenHashing() {
        char[] nullPassword = null;
        assertThrows(OpenSearchSecurityException.class, () -> { passwordHasher.hash(nullPassword); });
    }

    @Test
    public void shouldHandleNullPasswordWhenChecking() {
        char[] nullPassword = null;
        assertThrows(OpenSearchSecurityException.class, () -> { passwordHasher.check(nullPassword, "some hash"); });
    }

    @Test
    public void shouldHandleEmptyHashWhenChecking() {
        String emptyHash = "";
        assertThrows(OpenSearchSecurityException.class, () -> { passwordHasher.check(password.toCharArray(), emptyHash); });
    }

    @Test
    public void shouldHandleNullHashWhenChecking() {
        String nullHash = null;
        assertThrows(OpenSearchSecurityException.class, () -> { passwordHasher.check(password.toCharArray(), nullHash); });
    }

    @Test
    public void shouldCleanupPasswordCharArray() {
        char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        passwordHasher.hash(password);
        assertThat("\0\0\0\0\0\0\0\0", is(new String(password)));
    }

    @Test
    public void shouldCleanupPasswordCharBuffer() {
        char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        passwordHasher.hash(password);
        assertThat("\0\0\0\0\0\0\0\0", is(new String(password)));
        assertThat("\0\0\0\0\0\0\0\0", is(passwordBuffer.toString()));
    }
}
