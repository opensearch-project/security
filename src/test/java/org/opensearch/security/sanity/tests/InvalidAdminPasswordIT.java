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

    static String currentPasswordVariable = System.getProperty("password");

    @BeforeClass
    public static void setUpAdminAsPasswordVariable() {
        System.setProperty("password", "admin");
    }

    @AfterClass
    public static void restorePasswordProperty() {
        System.setProperty("password", currentPasswordVariable);
    }

    @Test
    public void testAdminCredentials_adminAsPassword_shouldFail() throws Exception {
        try {
            client().performRequest(new Request("GET", ""));
        } catch (ResponseException e) {
            Response res = e.getResponse();
            MatcherAssert.assertThat(res.getStatusLine().getStatusCode(), is(equalTo(401)));
            MatcherAssert.assertThat(res.getStatusLine().getReasonPhrase(), is(equalTo("Unauthorized")));
        }
    }
}
