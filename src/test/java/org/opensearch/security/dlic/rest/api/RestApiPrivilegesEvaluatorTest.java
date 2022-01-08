/*
 * Copyright OpenSearch Contributors
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

package org.opensearch.security.dlic.rest.api;

import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;
import org.opensearch.threadpool.ThreadPool;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

public class RestApiPrivilegesEvaluatorTest {

    private RestApiPrivilegesEvaluator privilegesEvaluator;

    @Before
    public void setUp() {
        this.privilegesEvaluator = new RestApiPrivilegesEvaluator(Settings.EMPTY,
                mock(AdminDNs.class),
                mock(PrivilegesEvaluator.class),
                mock(PrincipalExtractor.class),
                mock(Path.class),
                mock(ThreadPool.class));
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
