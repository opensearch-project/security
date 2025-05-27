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

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.SecurityConfigVersionsLoader;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.support.ConfigConstants.SECURITY_CONFIG_VERSION_INDEX_ENABLED;
import static org.mockito.Mockito.mock;

public class RollbackVersionApiActionValidationTest extends AbstractApiActionValidationTest {

    private RollbackVersionApiAction rollbackVersionApiAction;
    private Client client;

    @Before
    public void setupTest() {
        Settings settings = Settings.builder().put(SECURITY_CONFIG_VERSION_INDEX_ENABLED, true).build();

        securityApiDependencies = new SecurityApiDependencies(
            null,
            configurationRepository,
            null,
            null,
            restApiAdminPrivilegesEvaluator,
            null,
            settings
        );

        SecurityConfigVersionsLoader versionsLoader = mock(SecurityConfigVersionsLoader.class);
        client = mock(Client.class);

        rollbackVersionApiAction = new RollbackVersionApiAction(
            clusterService,
            threadPool,
            securityApiDependencies,
            versionsLoader,
            configurationRepository,
            client
        );
    }

    @Test
    public void testOnConfigDelete_isForbidden() throws IOException {
        var result = rollbackVersionApiAction.createEndpointValidator().onConfigDelete(SecurityConfiguration.of(null, configuration));
        assertThat(result.status(), is(org.opensearch.core.rest.RestStatus.FORBIDDEN));
    }

    @Test
    public void testOnConfigLoad_isAllowed() throws IOException {
        var result = rollbackVersionApiAction.createEndpointValidator().onConfigLoad(SecurityConfiguration.of(null, configuration));
        assertThat(result.status(), is(org.opensearch.core.rest.RestStatus.OK));
    }

    @Test
    public void testOnConfigChange_isAllowed() throws IOException {
        var result = rollbackVersionApiAction.createEndpointValidator().onConfigChange(SecurityConfiguration.of(null, configuration));
        assertThat(result.status(), is(org.opensearch.core.rest.RestStatus.OK));
    }

}
