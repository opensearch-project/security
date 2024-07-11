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
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.opensearch.SpecialPermission;

import com.password4j.CompressedPBKDF2Function;
import com.password4j.HashingFunction;
import com.password4j.Password;

class PBKDF2PasswordHasher extends AbstractPasswordHasher {

    private static final int DEFAULT_SALT_LENGTH = 128;

    @SuppressWarnings("removal")
    PBKDF2PasswordHasher(String function, int iterations, int length) {
        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkPermission(new SpecialPermission());
        }
        this.hashingFunction = AccessController.doPrivileged(
            (PrivilegedAction<HashingFunction>) () -> CompressedPBKDF2Function.getInstance(function, iterations, length)
        );
    }

    @Override
    @SuppressWarnings("removal")
    public String hash(char[] password) {
        checkPasswordNotNullOrEmpty(password);
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            SecurityManager securityManager = System.getSecurityManager();
            if (securityManager != null) {
                securityManager.checkPermission(new SpecialPermission());
            }
            return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> Password.hash(passwordBuffer)
                    .addRandomSalt(DEFAULT_SALT_LENGTH)
                    .with(hashingFunction)
                    .getResult()
            );
        } finally {
            cleanup(passwordBuffer);
        }
    }

    @SuppressWarnings("removal")
    @Override
    public boolean check(char[] password, String hash) {
        checkPasswordNotNullOrEmpty(password);
        checkHashNotNullOrEmpty(hash);
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            SecurityManager securityManager = System.getSecurityManager();
            if (securityManager != null) {
                securityManager.checkPermission(new SpecialPermission());
            }
            return AccessController.doPrivileged(
                (PrivilegedAction<Boolean>) () -> Password.check(passwordBuffer, hash).with(getPBKDF2FunctionFromHash(hash))
            );
        } finally {
            cleanup(passwordBuffer);
        }
    }

    private HashingFunction getPBKDF2FunctionFromHash(String hash) {
        return CompressedPBKDF2Function.getInstanceFromHash(hash);
    }
}
