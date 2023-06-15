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

package org.opensearch.security.configuration;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import com.google.common.annotations.VisibleForTesting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

/**
 * Configuration class to store salt used for FLS anonymization
 */
public class Salt {

    private static final Logger log = LogManager.getLogger(Salt.class);

    @VisibleForTesting
    static final int SALT_SIZE = 16;

    private final byte[] salt16;

    public Salt(final byte[] salt) {
        if (salt.length != SALT_SIZE) {
            throw new OpenSearchException("Provided compliance salt must contain 16 bytes");
        }
        this.salt16 = salt;
    }

    private Salt(final String saltAsString) {
        this.salt16 = new byte[SALT_SIZE];
        if (saltAsString.equals(ConfigConstants.SECURITY_COMPLIANCE_SALT_DEFAULT)) {
            log.warn(
                "If you plan to use field masking pls configure compliance salt {} to be a random string of 16 chars length identical on all nodes",
                saltAsString
            );
        }
        try {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(saltAsString);
            byteBuffer.get(salt16);
            if (byteBuffer.remaining() > 0) {
                log.warn(
                    "Provided compliance salt {} is greater than 16 bytes. Only the first 16 bytes are used for salting",
                    saltAsString
                );
            }
        } catch (BufferUnderflowException e) {
            throw new OpenSearchException("Provided compliance salt " + saltAsString + " must at least contain 16 bytes", e);
        }
    }

    /**
     * Get the salt in bytes for field anonymization.
     * Returns a new salt array every time it is called.
     * @return salt in bytes
     */
    byte[] getSalt16() {
        return salt16;
    }

    /**
     * Get salt configuration from OpenSearch settings
     * @param settings OpenSearch settings
     * @return configuration
     */
    public static Salt from(final Settings settings) {
        final String saltAsString = settings.get(
            ConfigConstants.SECURITY_COMPLIANCE_SALT,
            ConfigConstants.SECURITY_COMPLIANCE_SALT_DEFAULT
        );
        return new Salt(saltAsString);
    }
}
