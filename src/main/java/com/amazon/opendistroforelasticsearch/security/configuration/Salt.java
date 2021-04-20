/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.configuration;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.annotations.VisibleForTesting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

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
        if (saltAsString.equals(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT)) {
            log.warn("If you plan to use field masking pls configure compliance salt {} to be a random string of 16 chars length identical on all nodes", saltAsString);
        }
        try {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(saltAsString);
            byteBuffer.get(salt16);
            if (byteBuffer.remaining() > 0) {
                log.warn("Provided compliance salt {} is greater than 16 bytes. Only the first 16 bytes are used for salting", saltAsString);
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
        final String saltAsString = settings.get(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT);
        return new Salt(saltAsString);
    }
}
