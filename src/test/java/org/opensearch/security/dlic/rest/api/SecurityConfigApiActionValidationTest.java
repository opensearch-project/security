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

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.util.FakeRestRequest;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

public class SecurityConfigApiActionValidationTest extends AbstractApiActionValidationTest {

    @Test
    public void accessHandlerForDefaultSettings() {
        final var securityConfigApiAction = new SecurityConfigApiAction(
            clusterService,
            threadPool,
            new SecurityApiDependencies(null, configurationRepository, null, null, restApiAdminPrivilegesEvaluator, null, Settings.EMPTY)
        );
        assertTrue(securityConfigApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.GET).build()));
        assertFalse(securityConfigApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.PUT).build()));
        assertFalse(securityConfigApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.PATCH).build()));
    }

    @Test
    public void accessHandlerForUnsupportedSetting() {
        final var securityConfigApiAction = new SecurityConfigApiAction(
            clusterService,
            threadPool,
            new SecurityApiDependencies(
                null,
                configurationRepository,
                null,
                null,
                restApiAdminPrivilegesEvaluator,
                null,
                Settings.builder().put(SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build()
            )
        );
        assertTrue(securityConfigApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.GET).build()));
        assertTrue(securityConfigApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.PUT).build()));
        assertTrue(securityConfigApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.PATCH).build()));
    }

    @Test
    public void accessHandlerForRestAdmin() {
        when(restApiAdminPrivilegesEvaluator.isCurrentUserAdminFor(Endpoint.CONFIG, RestApiAdminPrivilegesEvaluator.SECURITY_CONFIG_UPDATE)).thenReturn(true);
        final var securityConfigApiAction = new SecurityConfigApiAction(
                clusterService,
                threadPool,
                new SecurityApiDependencies(
                        null,
                        configurationRepository,
                        null,
                        null,
                        restApiAdminPrivilegesEvaluator,
                        null,
                        Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build()
                )
        );
        assertTrue(securityConfigApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.GET).build()));
        assertTrue(securityConfigApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.PUT).build()));
        assertTrue(securityConfigApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.PATCH).build()));
    }
}
