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

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.opensearch.security.support.ConfigConstants.BCRYPT;
import static org.opensearch.security.support.ConfigConstants.PBKDF2;

public class PasswordHasherFactory {

    public static PasswordHasher createPasswordHasher(Settings settings) {

        String algorithm = settings.get(
            ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM,
            ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM_DEFAULT
        );

        PasswordHasher passwordHasher;
        switch (algorithm.toLowerCase()) {
            case BCRYPT:
                passwordHasher = getBCryptHasher(settings);
                break;
            case PBKDF2:
                passwordHasher = getPBKDF2Hasher(settings);
                break;
            default:
                throw new IllegalArgumentException("Password hashing algorithm not supported");
        }
        return passwordHasher;
    }

    private static PasswordHasher getBCryptHasher(Settings settings) {
        int rounds = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS,
            ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS_DEFAULT
        );
        String minor = settings.get(
            ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_MINOR,
            ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_MINOR_DEFAULT
        ).toUpperCase();

        if (rounds < 4 || rounds > 31) {
            throw new IllegalArgumentException("BCrypt rounds must be between 4 and 31.");
        }
        if (!minor.equals("A") && !minor.equals("B") && !minor.equals("Y")) {
            throw new IllegalArgumentException("BCrypt minor must be 'a', 'b', or 'y'.");
        }
        return new BCryptPasswordHasher(minor, rounds);
    }

    private static PasswordHasher getPBKDF2Hasher(Settings settings) {
        String pbkdf2Function = settings.get(
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION_DEFAULT
        ).toUpperCase();

        int iterations = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS_DEFAULT
        );
        int length = settings.getAsInt(
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH,
            ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH_DEFAULT
        );

        // todo: validate validation
        if (!pbkdf2Function.matches("SHA(1|224|256|384|512)")) {
            throw new IllegalArgumentException("PBKDF2 function must be one of SHA1, SHA224, SHA256, SHA384, or SHA512.");
        }
        if (iterations <= 0) {
            throw new IllegalArgumentException("PBKDF2 iterations must be a positive integer.");
        }
        if (length <= 0) {
            throw new IllegalArgumentException("PBKDF2 length must be a positive integer.");
        }
        return new PBKDF2PasswordHasher(pbkdf2Function, iterations, length);
    }
}
