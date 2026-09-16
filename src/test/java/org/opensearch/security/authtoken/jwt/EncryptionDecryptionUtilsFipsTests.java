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

package org.opensearch.security.authtoken.jwt;

import java.util.Base64;

import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

/**
 * FIPS variant of {@link EncryptionDecryptionUtilsTest}. Under FIPS the input key material
 * backing the derived AES-256 key must be at least 256 bits, which is not enforced otherwise.
 */
public class EncryptionDecryptionUtilsFipsTests extends EncryptionDecryptionUtilsTest {

    @Test
    public void testRejectsWeakEncryptionKey() {
        // 16-byte (128-bit) key material — below the 256-bit minimum required to back the derived AES-256 key
        String weakSecret = Base64.getEncoder().encodeToString("mySecretKey12345".getBytes());

        IllegalArgumentException ex = Assert.assertThrows(IllegalArgumentException.class, () -> new EncryptionDecryptionUtil(weakSecret));
        assertThat(ex.getMessage(), containsString("decodes to 16 bytes of key material, but FIPS mode requires at least 32 bytes"));
    }

    @Test
    public void testAcceptsStrongEncryptionKey() {
        // 32-byte (256-bit) key material satisfies the FIPS minimum
        String strongSecret = Base64.getEncoder().encodeToString("mySecretKey12345mySecretKey12345".getBytes());
        String data = "Hello, OpenSearch!";

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(strongSecret);

        assertThat(util.decrypt(util.encrypt(data)), is(data));
    }
}
