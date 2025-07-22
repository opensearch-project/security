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

import com.password4j.BcryptFunction;
import com.password4j.HashingFunction;
import com.password4j.Password;
import com.password4j.types.Bcrypt;

class BCryptPasswordHasher extends AbstractPasswordHasher {

    BCryptPasswordHasher(String minor, int logRounds) {
        this.hashingFunction = BcryptFunction.getInstance(Bcrypt.valueOf(minor), logRounds);
    }

    @Override
    public String hash(char[] password) {
        checkPasswordNotNullOrEmpty(password);
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            return Password.hash(passwordBuffer).with(hashingFunction).getResult();
        } finally {
            cleanup(passwordBuffer);
        }
    }

    @Override
    public boolean check(char[] password, String hash) {
        checkPasswordNotNullOrEmpty(password);
        checkHashNotNullOrEmpty(hash);
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            return Password.check(passwordBuffer, hash).with(getBCryptFunctionFromHash(hash));
        } finally {
            cleanup(passwordBuffer);
        }
    }

    private HashingFunction getBCryptFunctionFromHash(String hash) {
        return BcryptFunction.getInstanceFromHash(hash);
    }
}
