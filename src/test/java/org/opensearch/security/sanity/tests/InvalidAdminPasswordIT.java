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

package org.opensearch.security.sanity.tests;

import org.hamcrest.MatcherAssert;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class InvalidAdminPasswordIT extends SecurityRestTestCase {

    @BeforeClass
    public static void setUpInvalidAdminCredentials() {
        useAdminAsPassword = true;
    }

    @AfterClass
    public static void restoreValidAdminCredentials() {
        useAdminAsPassword = false;
    }

    @Test
    public void testAdminCredentials_adminPassword_shouldFail() throws Exception {
        try {
            client().performRequest(new Request("GET", ""));
        } catch (ResponseException e) {
            Response res = e.getResponse();
            MatcherAssert.assertThat(res.getStatusLine().getStatusCode(), is(equalTo(401)));
            MatcherAssert.assertThat(res.getStatusLine().getReasonPhrase(), is(equalTo("Unauthorized")));
        }
    }
}
