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

import java.nio.charset.StandardCharsets;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.opensearch.security.configuration.Salt.SALT_SIZE;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SaltTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testDefault() {
        // act
        final Salt salt = Salt.from(Settings.EMPTY);

        // assert
        assertEquals(SALT_SIZE, salt.getSalt16().length);
        assertArrayEquals(ConfigConstants.SECURITY_COMPLIANCE_SALT_DEFAULT.getBytes(StandardCharsets.UTF_8), salt.getSalt16());
    }

    @Test
    public void testConfig() {
        // arrange
        final String testSalt = "abcdefghijklmnop";
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_COMPLIANCE_SALT, testSalt).build();

        // act
        final Salt salt = Salt.from(settings);

        // assert
        assertArrayEquals(testSalt.getBytes(StandardCharsets.UTF_8), salt.getSalt16());
        assertEquals(SALT_SIZE, salt.getSalt16().length);
    }

    @Test
    public void testSaltUsesOnlyFirst16Bytes() {
        // arrange
        final String testSalt = "abcdefghijklmnopqrstuvwxyz";
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_COMPLIANCE_SALT, testSalt).build();
        // act
        final Salt salt = Salt.from(settings);

        // assert
        assertEquals(SALT_SIZE, salt.getSalt16().length);
        assertArrayEquals(testSalt.substring(0, SALT_SIZE).getBytes(StandardCharsets.UTF_8), salt.getSalt16());
    }

    @Test
    public void testSaltThrowsExceptionWhenInsufficientBytesProvided() {
        // assert
        thrown.expect(OpenSearchException.class);
        thrown.expectMessage("Provided compliance salt abcd must at least contain 16 bytes");

        // arrange
        final String testSalt = "abcd";
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_COMPLIANCE_SALT, testSalt).build();
        // act
        final Salt salt = Salt.from(settings);
    }

    @Test
    public void testSaltThrowsExceptionWhenInsufficientBytesArrayProvided() {
        // assert
        thrown.expect(OpenSearchException.class);
        thrown.expectMessage("Provided compliance salt must contain 16 bytes");

        // act
        new Salt(new byte[] { 1, 2, 3, 4, 5 });
    }

    @Test
    public void testSaltThrowsExceptionWhenExcessBytesArrayProvided() {
        // assert
        thrown.expect(OpenSearchException.class);
        thrown.expectMessage("Provided compliance salt must contain 16 bytes");

        // act
        new Salt(new byte[] { 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5 });
    }

    @Test
    public void testSaltThrowsNoExceptionWhenCorrectBytesArrayProvided() {
        // act
        new Salt(new byte[] { 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1 });
    }
}
