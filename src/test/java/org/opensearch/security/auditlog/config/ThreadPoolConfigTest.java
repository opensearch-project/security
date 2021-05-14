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

package org.opensearch.security.auditlog.config;

import org.opensearch.common.settings.Settings;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.assertEquals;

public class ThreadPoolConfigTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testIncorrectThreadPoolSizeThrowsException() {
        // arrange
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Incorrect thread pool size: -1 configured for audit logging.");
        // act
        new ThreadPoolConfig(-1, 2);
    }

    @Test
    public void testIncorrectQueueLengthThrowsException() {
        // arrange
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Incorrect thread pool queue length: -2 configured for audit logging.");
        // act
        new ThreadPoolConfig(1, -2);
    }

    @Test
    public void testZeroThreadPoolSizeThrowsException() {
        // arrange
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Incorrect thread pool size: 0 configured for audit logging.");
        // act
        new ThreadPoolConfig(0, 1);
    }

    @Test
    public void testZeroQueueLengthThrowsException() {
        // arrange
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Incorrect thread pool queue length: 0 configured for audit logging.");
        // act
        new ThreadPoolConfig(1, 0);
    }

    @Test
    public void testConfig() {
        // arrange
        ThreadPoolConfig config = new ThreadPoolConfig(5, 200);

        // assert
        assertEquals(5, config.getThreadPoolSize());
        assertEquals(200, config.getThreadPoolMaxQueueLen());
    }

    @Test
    public void testGenerationFromSettings() {
        // arrange
        Settings settings = Settings.builder()
                .put("opendistro_security.audit.threadpool.size", "8")
                .put("opendistro_security.audit.threadpool.max_queue_len", "50")
                .build();

        // assert
        ThreadPoolConfig config = ThreadPoolConfig.getConfig(settings);
        assertEquals(8, config.getThreadPoolSize());
        assertEquals(50, config.getThreadPoolMaxQueueLen());
    }
}
