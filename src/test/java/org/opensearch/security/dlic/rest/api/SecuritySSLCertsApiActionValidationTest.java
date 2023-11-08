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

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.util.FakeRestRequest;

import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.CERTS_INFO_ACTION;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.RELOAD_CERTS_ACTION;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

public class SecuritySSLCertsApiActionValidationTest extends AbstractApiActionValidationTest {

    @Test
    public void withSecurityKeyStore() {
        final var securitySSLCertsApiAction = new SecuritySSLCertsApiAction(
            clusterService,
            threadPool,
            null,
            true,
            securityApiDependencies
        );
        final var result = securitySSLCertsApiAction.withSecurityKeyStore();
        assertFalse(result.isValid());
        assertEquals(RestStatus.OK, result.status());
    }

    @Test
    public void accessDenied() {
        final var securitySSLCertsApiAction = new SecuritySSLCertsApiAction(
            clusterService,
            threadPool,
            null,
            true,
            securityApiDependencies
        );
        when(restApiAdminPrivilegesEvaluator.isCurrentUserAdminFor(Endpoint.SSL, CERTS_INFO_ACTION)).thenReturn(false);
        when(restApiAdminPrivilegesEvaluator.isCurrentUserAdminFor(Endpoint.SSL, RELOAD_CERTS_ACTION)).thenReturn(false);
        assertFalse(securitySSLCertsApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.GET).build()));
        assertFalse(securitySSLCertsApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.PUT).build()));

        for (final var m : RequestHandler.RequestHandlersBuilder.SUPPORTED_METHODS) {
            if (m != RestRequest.Method.GET && m != RestRequest.Method.PUT) {
                assertFalse(securitySSLCertsApiAction.accessHandler(FakeRestRequest.builder().withMethod(m).build()));
            }
        }
    }

    @Test
    public void hasAccess() {
        final var securitySSLCertsApiAction = new SecuritySSLCertsApiAction(
            clusterService,
            threadPool,
            null,
            true,
            securityApiDependencies
        );
        when(restApiAdminPrivilegesEvaluator.isCurrentUserAdminFor(Endpoint.SSL, CERTS_INFO_ACTION)).thenReturn(true);
        when(restApiAdminPrivilegesEvaluator.isCurrentUserAdminFor(Endpoint.SSL, RELOAD_CERTS_ACTION)).thenReturn(true);
        assertTrue(securitySSLCertsApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.GET).build()));
        assertTrue(securitySSLCertsApiAction.accessHandler(FakeRestRequest.builder().withMethod(RestRequest.Method.PUT).build()));

        for (final var m : RequestHandler.RequestHandlersBuilder.SUPPORTED_METHODS) {
            if (m != RestRequest.Method.GET && m != RestRequest.Method.PUT) {
                assertFalse(securitySSLCertsApiAction.accessHandler(FakeRestRequest.builder().withMethod(m).build()));
            }
        }
    }

}
