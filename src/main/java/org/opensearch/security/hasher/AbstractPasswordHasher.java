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

import com.password4j.HashingFunction;

abstract class AbstractPasswordHasher implements PasswordHasher {

    HashingFunction hashingFunction;

    public abstract String hash(char[] password);

    public abstract boolean check(char[] password, String hash);

    protected void cleanup(CharBuffer password) {
        password.clear();
        char[] passwordOverwrite = new char[password.capacity()];
        Arrays.fill(passwordOverwrite, '\0');
        password.put(passwordOverwrite);
    }
}
