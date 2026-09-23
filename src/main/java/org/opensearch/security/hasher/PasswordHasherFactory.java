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

import java.util.Set;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Setting.Property;
import org.opensearch.common.settings.Settings;

public class PasswordHasherFactory {

    public static final String BCRYPT = "bcrypt";
    public static final String PBKDF2 = "pbkdf2";
    public static final String ARGON2 = "argon2";

    /** BCrypt logarithmic work factor. */
    public static final Setting<Integer> BCRYPT_ROUNDS = Setting.intSetting(
        "plugins.security.password.hashing.bcrypt.rounds",
        12,
        Property.NodeScope,
        Property.Final
    );

    /** BCrypt minor version. */
    public static final Setting<String> BCRYPT_MINOR = Setting.simpleString(
        "plugins.security.password.hashing.bcrypt.minor",
        "Y",
        Property.NodeScope,
        Property.Final
    );

    /** Algorithm used to hash new passwords. */
    public static final Setting<String> ALGORITHM = Setting.simpleString(
        "plugins.security.password.hashing.algorithm",
        BCRYPT,
        Property.NodeScope,
        Property.Final
    );

    /** PBKDF2 iteration count. */
    public static final Setting<Integer> PBKDF2_ITERATIONS = Setting.intSetting(
        "plugins.security.password.hashing.pbkdf2.iterations",
        600_000,
        Property.NodeScope,
        Property.Final
    );

    /** PBKDF2 derived key length in bits. */
    public static final Setting<Integer> PBKDF2_LENGTH = Setting.intSetting(
        "plugins.security.password.hashing.pbkdf2.length",
        256,
        Property.NodeScope,
        Property.Final
    );

    /** PBKDF2 HMAC function. */
    public static final Setting<String> PBKDF2_FUNCTION = Setting.simpleString(
        "plugins.security.password.hashing.pbkdf2.function",
        "SHA256",
        Property.NodeScope,
        Property.Final
    );

    /** Argon2 iteration count. */
    public static final Setting<Integer> ARGON2_ITERATIONS = Setting.intSetting(
        "plugins.security.password.hashing.argon2.iterations",
        3,
        Property.NodeScope,
        Property.Final
    );

    /** Argon2 memory cost in KiB. */
    public static final Setting<Integer> ARGON2_MEMORY = Setting.intSetting(
        "plugins.security.password.hashing.argon2.memory",
        65536,
        Property.NodeScope,
        Property.Final
    );

    /** Argon2 parallelism. */
    public static final Setting<Integer> ARGON2_PARALLELISM = Setting.intSetting(
        "plugins.security.password.hashing.argon2.parallelism",
        1,
        Property.NodeScope,
        Property.Final
    );

    /** Argon2 hash length in bytes. */
    public static final Setting<Integer> ARGON2_LENGTH = Setting.intSetting(
        "plugins.security.password.hashing.argon2.length",
        32,
        Property.NodeScope,
        Property.Final
    );

    /** Argon2 variant. */
    public static final Setting<String> ARGON2_TYPE = Setting.simpleString(
        "plugins.security.password.hashing.argon2.type",
        "argon2id",
        Property.NodeScope,
        Property.Final
    );

    /** Argon2 version number. */
    public static final Setting<Integer> ARGON2_VERSION = Setting.intSetting(
        "plugins.security.password.hashing.argon2.version",
        19,
        Property.NodeScope,
        Property.Final
    );

    private static final Set<String> ALLOWED_BCRYPT_MINORS = Set.of("A", "B", "Y");

    public static PasswordHasher createPasswordHasher(Settings settings) {
        String algorithm = ALGORITHM.get(settings);

        PasswordHasher passwordHasher;
        switch (algorithm.toLowerCase()) {
            case BCRYPT:
                passwordHasher = getBCryptHasher(settings);
                break;
            case PBKDF2:
                passwordHasher = getPBKDF2Hasher(settings);
                break;
            case ARGON2:
                passwordHasher = getArgon2Hasher(settings);
                break;
            default:
                throw new IllegalArgumentException(String.format("Password hashing algorithm '%s' not supported.", algorithm));
        }
        return passwordHasher;
    }

    private static PasswordHasher getBCryptHasher(Settings settings) {
        int rounds = BCRYPT_ROUNDS.get(settings);
        String minor = BCRYPT_MINOR.get(settings).toUpperCase();

        if (rounds < 4 || rounds > 31) {
            throw new IllegalArgumentException(String.format("BCrypt rounds must be between 4 and 31. Got: %d", rounds));
        }
        if (!ALLOWED_BCRYPT_MINORS.contains(minor)) {
            throw new IllegalArgumentException(String.format("BCrypt minor must be 'A', 'B', or 'Y'. Got: %s", minor));
        }
        return new BCryptPasswordHasher(minor, rounds);
    }

    private static PasswordHasher getPBKDF2Hasher(Settings settings) {
        String pbkdf2Function = PBKDF2_FUNCTION.get(settings).toUpperCase();

        int iterations = PBKDF2_ITERATIONS.get(settings);
        int length = PBKDF2_LENGTH.get(settings);

        if (!pbkdf2Function.matches("SHA(1|224|256|384|512)")) {
            throw new IllegalArgumentException(
                String.format("PBKDF2 function must be one of SHA1, SHA224, SHA256, SHA384, or SHA512. Got: %s", pbkdf2Function)
            );
        }
        if (iterations <= 0) {
            throw new IllegalArgumentException(String.format("PBKDF2 iterations must be a positive integer. Got: %d", iterations));
        }
        if (length <= 0) {
            throw new IllegalArgumentException(String.format("PBKDF2 length must be a positive integer. Got: %d", length));
        }
        return new PBKDF2PasswordHasher(pbkdf2Function, iterations, length);
    }

    private static PasswordHasher getArgon2Hasher(Settings settings) {
        int memory = ARGON2_MEMORY.get(settings);
        int iterations = ARGON2_ITERATIONS.get(settings);
        int parallelism = ARGON2_PARALLELISM.get(settings);
        int length = ARGON2_LENGTH.get(settings);
        String type = ARGON2_TYPE.get(settings);
        int version = ARGON2_VERSION.get(settings);

        if (memory <= 0) {
            throw new IllegalArgumentException(String.format("Argon2 memory must be a positive integer. Got: %d", memory));
        }
        if (iterations <= 0) {
            throw new IllegalArgumentException(String.format("Argon2 iterations must be a positive integer. Got: %d", iterations));
        }
        if (parallelism <= 0) {
            throw new IllegalArgumentException(String.format("Argon2 parallelism must be a positive integer. Got: %d", parallelism));
        }
        if (length <= 0) {
            throw new IllegalArgumentException(String.format("Argon2 length must be a positive integer. Got: %d", length));
        }
        String typeLower = type.toLowerCase();
        if (!typeLower.equals("argon2id") && !typeLower.equals("argon2i") && !typeLower.equals("argon2d")) {
            throw new IllegalArgumentException(String.format("Argon2 type must be one of argon2id, argon2i, or argon2d. Got: %s", type));
        }
        if (version != 16 && version != 19) {
            throw new IllegalArgumentException(String.format("Argon2 version must be either 16 or 19. Got: %d", version));
        }
        return new Argon2PasswordHasher(memory, iterations, parallelism, length, type, version);
    }
}
