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

package org.opensearch.security.action.apitokens;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ApiTokenActionTest {
    @Mock
    private ThreadPool threadPool;

    @Mock
    private PrivilegesConfiguration privilegesConfiguration;

    @Mock
    private ConfigurationRepository configurationRepository;

    private ApiTokenAction apiTokenAction;

    @Before
    public void setUp() throws JsonProcessingException {
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));

        apiTokenAction = new ApiTokenAction(
            threadPool,
            configurationRepository,
            privilegesConfiguration,
            Settings.EMPTY,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null
        );
    }

    @Test
    public void testGetName() {
        assert apiTokenAction.getName().equals("api_token_action");
    }
}
