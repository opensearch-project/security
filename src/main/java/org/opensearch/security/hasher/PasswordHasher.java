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

/**
 * Interface representing a password hasher which provides methods
 * to hash a password and check a password against a hashed password.
 */
public interface PasswordHasher {

    /**
     * Generates a hashed representation of the given password.
     *
     * @param password the password to hash
     * @return a hashed representation of the password
     */
    String hash(char[] password);

    /**
     * Checks if the given password matches the provided hashed password.
     *
     * @param password the password to check
     * @param hashedPassword the hashed password to check against
     * @return true if the password matches the hashed password, false otherwise
     */
    boolean check(char[] password, String hashedPassword);
}
