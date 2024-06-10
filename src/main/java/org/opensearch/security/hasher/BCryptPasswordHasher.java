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
import java.util.Arrays;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;

import com.password4j.BcryptFunction;
import com.password4j.HashingFunction;
import com.password4j.Password;
import com.password4j.types.Bcrypt;

import static org.opensearch.core.common.Strings.isNullOrEmpty;

public class BCryptPasswordHasher implements PasswordHasher {

    private static final HashingFunction DEFAULT_BCRYPT_FUNCTION = BcryptFunction.getInstance(Bcrypt.Y, 12);

    @Override
    public String hash(char[] password) {
        if (password == null || password.length == 0) {
            throw new OpenSearchSecurityException("Password cannot be empty or null");
        }
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            SecurityManager securityManager = System.getSecurityManager();
            if (securityManager != null) {
                securityManager.checkPermission(new SpecialPermission());
            }
            return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> Password.hash(passwordBuffer).with(DEFAULT_BCRYPT_FUNCTION).getResult()
            );
        } finally {
            cleanup(passwordBuffer);
        }
    }

    @Override
    public boolean check(char[] password, String hash) {
        if (password == null || password.length == 0) {
            throw new OpenSearchSecurityException("Password cannot be empty or null");
        }
        if (isNullOrEmpty(hash)) {
            throw new OpenSearchSecurityException("Hash cannot be empty or null");
        }
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            SecurityManager securityManager = System.getSecurityManager();
            if (securityManager != null) {
                securityManager.checkPermission(new SpecialPermission());
            }
            return AccessController.doPrivileged(
                (PrivilegedAction<Boolean>) () -> Password.check(passwordBuffer, hash).with(getBCryptFunctionFromHash(hash))
            );
        } finally {
            cleanup(passwordBuffer);
        }
    }

    private void cleanup(CharBuffer password) {
        password.clear();
        char[] passwordOverwrite = new char[password.capacity()];
        Arrays.fill(passwordOverwrite, '\0');
        password.put(passwordOverwrite);
    }

    private HashingFunction getBCryptFunctionFromHash(String hash) {
        return BcryptFunction.getInstanceFromHash(hash);
    }
}
