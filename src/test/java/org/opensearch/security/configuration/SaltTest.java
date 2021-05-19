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

package org.opensearch.security.configuration;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;

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
        assertArrayEquals(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT.getBytes(StandardCharsets.UTF_8), salt.getSalt16());
    }

    @Test
    public void testConfig() {
        // arrange
        final String testSalt = "abcdefghijklmnop";
        final Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, testSalt)
                .build();

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
        final Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, testSalt)
                .build();
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
        final Settings settings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, testSalt)
                .build();
        // act
        final Salt salt = Salt.from(settings);
    }

    @Test
    public void testSaltThrowsExceptionWhenInsufficientBytesArrayProvided() {
        // assert
        thrown.expect(OpenSearchException.class);
        thrown.expectMessage("Provided compliance salt must contain 16 bytes");

        // act
        new Salt(new byte[]{1, 2, 3, 4, 5});
    }

    @Test
    public void testSaltThrowsExceptionWhenExcessBytesArrayProvided() {
        // assert
        thrown.expect(OpenSearchException.class);
        thrown.expectMessage("Provided compliance salt must contain 16 bytes");

        // act
        new Salt(new byte[]{1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5});
    }

    @Test
    public void testSaltThrowsNoExceptionWhenCorrectBytesArrayProvided() {
        // act
        new Salt(new byte[]{1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1});
    }
}
