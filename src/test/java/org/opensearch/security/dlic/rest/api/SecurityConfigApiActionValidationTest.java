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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.support.ConfigConstants;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SecurityConfigApiActionValidationTest extends AbstractApiActionValidationTest {

    @Test
    public void configEntityNameOnly() {
        final var securityConfigApiAction = new SecurityConfigApiAction(clusterService, threadPool, securityApiDependencies);
        var result = securityConfigApiAction.withConfigEntityNameOnly(createRestRequest(RestRequest.Method.GET, Map.of("name", "aaaaa")));
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());

        result = securityConfigApiAction.withConfigEntityNameOnly(createRestRequest(RestRequest.Method.GET, Map.of("name", "config")));
        assertTrue(result.isValid());
    }

    @Test
    public void withAllowedEndpoint() {
        var securityConfigApiAction = new SecurityConfigApiAction(
            clusterService,
            threadPool,
            new SecurityApiDependencies(null, configurationRepository, null, null, restApiAdminPrivilegesEvaluator, null, Settings.EMPTY)
        );

        var result = securityConfigApiAction.withAllowedEndpoint(createRestRequest(RestRequest.Method.GET, Map.of()));
        assertFalse(result.isValid());
        assertEquals(RestStatus.NOT_IMPLEMENTED, result.status());

        securityConfigApiAction = new SecurityConfigApiAction(
            clusterService,
            threadPool,
            new SecurityApiDependencies(
                null,
                configurationRepository,
                null,
                null,
                restApiAdminPrivilegesEvaluator,
                null,
                Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build()
            )
        );
        result = securityConfigApiAction.withAllowedEndpoint(createRestRequest(RestRequest.Method.GET, Map.of()));
        assertTrue(result.isValid());
    }

}
