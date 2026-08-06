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

import org.apache.lucene.tests.util.LuceneTestCase;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

public abstract class AbstractPasswordHasherTests extends LuceneTestCase {

    PasswordHasher passwordHasher;

    final String wrongPassword = "wrongTestPassword";

    protected String getPassword() {
        return "testPassword";
    }

    @Test
    public void shouldMatchHashToCorrectPassword() {
        String hashedPassword = passwordHasher.hash(getPassword().toCharArray());
        assertThat(passwordHasher.check(getPassword().toCharArray(), hashedPassword), is(true));
    }

    @Test
    public void shouldNotMatchHashToWrongPassword() {
        String hashedPassword = passwordHasher.hash(getPassword().toCharArray());
        assertThat(passwordHasher.check(wrongPassword.toCharArray(), hashedPassword), is(false));

    }

    @Test
    public void shouldGenerateDifferentHashesForTheSamePassword() {
        String hash1 = passwordHasher.hash(getPassword().toCharArray());
        String hash2 = passwordHasher.hash(getPassword().toCharArray());
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
        assertThrows(OpenSearchSecurityException.class, () -> { passwordHasher.check(getPassword().toCharArray(), emptyHash); });
    }

    @Test
    public void shouldHandleNullHashWhenChecking() {
        String nullHash = null;
        assertThrows(OpenSearchSecurityException.class, () -> { passwordHasher.check(getPassword().toCharArray(), nullHash); });
    }

    @Test
    public void shouldCleanupPasswordCharArray() {
        char[] passwordAsChar = getPassword().toCharArray();
        passwordHasher.hash(passwordAsChar);
        assertThat("\0".repeat(getPassword().length()), is(new String(passwordAsChar)));
    }

    @Test
    public void shouldCleanupPasswordCharBuffer() {
        char[] passwordAsChar = getPassword().toCharArray();
        CharBuffer passwordBuffer = CharBuffer.wrap(passwordAsChar);
        passwordHasher.hash(passwordAsChar);
        assertThat("\0".repeat(getPassword().length()), is(new String(passwordAsChar)));
        assertThat("\0".repeat(getPassword().length()), is(passwordBuffer.toString()));
    }

}
