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
import java.util.Arrays;

import org.opensearch.OpenSearchSecurityException;

import com.password4j.HashingFunction;

import static org.opensearch.core.common.Strings.isNullOrEmpty;

/**
 * Abstract implementation of PasswordHasher interface
 */
abstract class AbstractPasswordHasher implements PasswordHasher {

    /**
     * The hashing function used by the hasher.
     */
    HashingFunction hashingFunction;

    /**
     * {@inheritDoc}
     */
    public abstract String hash(char[] password);

    /**
     * {@inheritDoc}
     */
    public abstract boolean check(char[] password, String hash);

    /**
     * Clears the given password buffer to prevent sensitive data from being left in memory.
     *
     * @param password the CharBuffer containing the password to clear
     */
    protected void cleanup(CharBuffer password) {
        password.clear();
        char[] passwordOverwrite = new char[password.capacity()];
        Arrays.fill(passwordOverwrite, '\0');
        password.put(passwordOverwrite);
    }

    /**
     * Checks if the given password is null or empty and throws an exception if it is.
     *
     * @param password the password to check
     * @throws OpenSearchSecurityException if the password is null or empty
     */
    protected void checkPasswordNotNullOrEmpty(char[] password) {
        if (password == null || password.length == 0) {
            throw new OpenSearchSecurityException("Password cannot be empty or null");
        }
    }

    /**
     * Checks if the given hash is null or empty and throws an exception if it is.
     *
     * @param hash the hash to check
     * @throws OpenSearchSecurityException if the hash is null or empty
     */
    protected void checkHashNotNullOrEmpty(String hash) {
        if (isNullOrEmpty(hash)) {
            throw new OpenSearchSecurityException("Hash cannot be empty or null");
        }
    }

}
