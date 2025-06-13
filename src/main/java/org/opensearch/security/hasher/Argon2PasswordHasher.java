package org.opensearch.security.hasher;

import java.nio.CharBuffer;
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.opensearch.SpecialPermission;

import com.password4j.Argon2Function;
import com.password4j.HashingFunction;
import com.password4j.Password;
import com.password4j.types.Argon2;

class Argon2PasswordHasher extends AbstractPasswordHasher{

    private final int memory;
    private final int iterations;
    private final int length;
    private final int parallelization;
    private final Argon2 typeArgon2;
    private final int version;

    private static final int DEFAULT_SALT_LENGTH = 128;

    @SuppressWarnings("removal")
    Argon2PasswordHasher(String type, int iterations, int memory, int parallelism, int length, int version) {
        this.iterations = iterations;
        this.memory = memory;
        this.parallelization = parallelism;
        this.length = length;
        this.typeArgon2 = parseType(type);
        this.version = version;

        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkPermission(new SpecialPermission());
        }
        this.hashingFunction = AccessController.doPrivileged(
            (PrivilegedAction<HashingFunction>) () ->
                Argon2Function.getInstance(
                    this.memory,
                    this.iterations,
                    this.parallelization,
                    this.length,
                    this.typeArgon2,
                    this.version
                )
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

    @Override
    @SuppressWarnings("removal")
    public boolean check(char[] password, String hash){
        checkPasswordNotNullOrEmpty(password);
        checkHashNotNullOrEmpty(hash);
        CharBuffer passwordBuffer = CharBuffer.wrap(password);
        try {
            SecurityManager securityManager = System.getSecurityManager();
            if (securityManager != null) {
                securityManager.checkPermission(new SpecialPermission());
            }
            return AccessController.doPrivileged(
                (PrivilegedAction<Boolean>) () -> Password.check(passwordBuffer, hash).with(getArgon2FunctionFromHash(hash))
            );
        } finally {
            cleanup(passwordBuffer);
        }
    }
    
    private HashingFunction getArgon2FunctionFromHash(String hash){
        return Argon2Function.getInstanceFromHash(hash);
    }

    private Argon2 parseType(String type) {
        if (type == null) {
            throw new IllegalArgumentException("Argon2 type cannot be null");
        }
        switch (type.toLowerCase()) {
            case "argon2id":
                return Argon2.ID;
            case "argon2i":
                return Argon2.I;
            case "argon2d":
                return Argon2.D;
            default:
                throw new IllegalArgumentException("Unknown Argon2 type: " + type);
        }
    }
    
}
