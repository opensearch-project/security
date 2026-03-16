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

import org.bouncycastle.crypto.CryptoServicesRegistrar;

import com.password4j.CompressedPBKDF2Function;
import com.password4j.HashingFunction;
import com.password4j.Password;

class PBKDF2PasswordHasher extends AbstractPasswordHasher {

    private static final int DEFAULT_SALT_LENGTH = 128;

    PBKDF2PasswordHasher(String function, int iterations, int length) {
        this.hashingFunction = CompressedPBKDF2Function.getInstance(function, iterations, length);
    }

    @Override
    public String hash(char[] password) {
        checkPasswordNotNullOrEmpty(password);
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            return Password.hash(passwordBuffer).addRandomSalt(DEFAULT_SALT_LENGTH).with(hashingFunction).getResult();
        } finally {
            cleanup(passwordBuffer);
        }
    }

    @Override
    public boolean check(char[] password, String hash) {
        checkPasswordNotNullOrEmpty(password);
        checkHashNotNullOrEmpty(hash);

        if (CryptoServicesRegistrar.isInApprovedOnlyMode() && password.length < 14) {
            return false;
        }

        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            return Password.check(passwordBuffer, hash).with(getPBKDF2FunctionFromHash(hash));
        } finally {
            cleanup(passwordBuffer);
        }
    }

    private HashingFunction getPBKDF2FunctionFromHash(String hash) {
        return CompressedPBKDF2Function.getInstanceFromHash(hash);
    }
}
