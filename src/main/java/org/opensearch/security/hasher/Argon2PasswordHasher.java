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

import com.password4j.Argon2Function;
import com.password4j.HashingFunction;
import com.password4j.Password;
import com.password4j.types.Argon2;

class Argon2PasswordHasher extends AbstractPasswordHasher {

    private final int memory;
    private final int iterations;
    private final int length;
    private final int parallelization;
    private final Argon2 typeArgon2;
    private final int version;

    private static final int DEFAULT_SALT_LENGTH = 128;

    Argon2PasswordHasher(int memory, int iterations, int parallelism, int length, String type, int version) {
        this.iterations = iterations;
        this.memory = memory;
        this.parallelization = parallelism;
        this.length = length;
        this.typeArgon2 = parseType(type);
        this.version = version;

        this.hashingFunction = Argon2Function.getInstance(
            this.memory,
            this.iterations,
            this.parallelization,
            this.length,
            this.typeArgon2,
            this.version
        );
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
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            return Password.check(passwordBuffer, hash).with(getArgon2FunctionFromHash(hash));
        } catch (Exception e) {
            return false;
        } finally {
            cleanup(passwordBuffer);
        }
    }

    private HashingFunction getArgon2FunctionFromHash(String hash) {
        return Argon2Function.getInstanceFromHash(hash);
    }

    private Argon2 parseType(String type) {
        if (type == null) {
            throw new IllegalArgumentException("Argon2 type can't be null");
        }
        switch (type.toUpperCase()) {
            case "ARGON2ID":
                return Argon2.ID;
            case "ARGON2I":
                return Argon2.I;
            case "ARGON2D":
                return Argon2.D;
            default:
                throw new IllegalArgumentException("Unknown Argon2 type: " + type);
        }
    }

}
