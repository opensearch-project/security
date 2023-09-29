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
import java.nio.file.Path;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

public class RestApiPrivilegesEvaluatorTest {

    private RestApiPrivilegesEvaluator privilegesEvaluator;

    @Before
    public void setUp() {
        this.privilegesEvaluator = new RestApiPrivilegesEvaluator(
            Settings.EMPTY,
            mock(AdminDNs.class),
            mock(PrivilegesEvaluator.class),
            mock(PrincipalExtractor.class),
            mock(Path.class),
            mock(ThreadPool.class)
        );
    }

    @Test
    public void testAccountEndpointBypass() throws IOException {
        // act
        String res = privilegesEvaluator.checkAccessPermissions(mock(RestRequest.class), Endpoint.ACCOUNT);
        // assert
        assertNull(res);

        res = privilegesEvaluator.checkAccessPermissions(mock(RestRequest.class), Endpoint.INTERNALUSERS);
        // assert
        assertNotNull(res);
    }
}
