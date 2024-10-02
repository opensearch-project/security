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

import org.apache.hc.core5.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.StringContains.containsString;

public class RateLimitersApiActionTest extends AbstractRestApiUnitTest {

    private static final Header ADMIN_FULL_ACCESS_USER = encodeBasicHeader("admin_all_access", "admin_all_access");
    private static final Header USER_NO_REST_API_ACCESS = encodeBasicHeader("admin", "admin");

    @Test
    public void testForbiddenAccess() throws Exception {
        setupWithRestRoles();

        rh.sendAdminCertificate = false;
        RestHelper.HttpResponse getSettingResponse = rh.executeGetRequest(
            "/_plugins/_security/api/authfailurelisteners",
            USER_NO_REST_API_ACCESS
        );
        assertThat(getSettingResponse.getBody(), getSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        RestHelper.HttpResponse updateSettingResponse = rh.executePutRequest(
            "/_plugins/_security/api/authfailurelisteners/test",
            "{\"type\":\"ip\",\"allowed_tries\":10,\"time_window_seconds\":3600,\"block_expiry_seconds\":600,\"max_blocked_clients\":100000,\"max_tracked_clients\":100000}",
            USER_NO_REST_API_ACCESS
        );
        assertThat(getSettingResponse.getBody(), updateSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        RestHelper.HttpResponse deleteSettingResponse = rh.executeDeleteRequest(
            "/_plugins/_security/api/authfailurelisteners/test",
            USER_NO_REST_API_ACCESS
        );
        assertThat(getSettingResponse.getBody(), updateSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
    }

    @Test
    public void testFullAccess() throws Exception {
        setupWithRestRoles();
        rh.sendAdminCertificate = true;
        // Initial get returns no auth failure listeners
        RestHelper.HttpResponse getAuthFailuresResponse = rh.executeGetRequest(
            "/_plugins/_security/api/authfailurelisteners",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(getAuthFailuresResponse.getBody(), getAuthFailuresResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(getAuthFailuresResponse.getBody(), getAuthFailuresResponse.getBody(), equalTo("{}"));

        // Put a test auth failure listener
        RestHelper.HttpResponse updateAuthFailuresResponse = rh.executePutRequest(
            "/_plugins/_security/api/authfailurelisteners/test",
            "{\"type\":\"ip\",\"allowed_tries\":10,\"time_window_seconds\":3600,\"block_expiry_seconds\":600,\"max_blocked_clients\":100000,\"max_tracked_clients\":100000}",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(updateAuthFailuresResponse.getBody(), updateAuthFailuresResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // Get after put returns the test auth failure listener
        RestHelper.HttpResponse getAuthFailuresResponseAfterPut = rh.executeGetRequest(
            "/_plugins/_security/api/authfailurelisteners",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(getAuthFailuresResponseAfterPut.getBody(), getAuthFailuresResponseAfterPut.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(
            getAuthFailuresResponseAfterPut.getBody(),
            getAuthFailuresResponseAfterPut.getBody(),
            equalTo(
                "{\"test\":{\"name\":\"test\",\"type\":\"ip\",\"ignore_hosts\":[],\"authentication_backend\":null,\"allowed_tries\":10,\"time_window_seconds\":3600,\"block_expiry_seconds\":600,\"max_blocked_clients\":100000,\"max_tracked_clients\":100000}}"
            )
        );

        // Delete the test auth failure listener
        RestHelper.HttpResponse deleteAuthFailuresResponse = rh.executeDeleteRequest(
            "/_plugins/_security/api/authfailurelisteners/test",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(deleteAuthFailuresResponse.getBody(), deleteAuthFailuresResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // Get after delete returns no auth failure listener
        RestHelper.HttpResponse getAuthFailuresResponseAfterDelete = rh.executeGetRequest(
            "/_plugins/_security/api/authfailurelisteners",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(
            getAuthFailuresResponseAfterDelete.getBody(),
            getAuthFailuresResponseAfterDelete.getStatusCode(),
            equalTo(HttpStatus.SC_OK)
        );
        assertThat(getAuthFailuresResponseAfterDelete.getBody(), getAuthFailuresResponseAfterDelete.getBody(), equalTo("{}"));
    }

    @Test
    public void testInvalidDeleteScenarios() throws Exception {
        setupWithRestRoles();

        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse deleteAuthFailuresResponseNoExist = rh.executeDeleteRequest(
            "/_plugins/_security/api/authfailurelisteners/test",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(
            deleteAuthFailuresResponseNoExist.getBody(),
            deleteAuthFailuresResponseNoExist.getStatusCode(),
            equalTo(HttpStatus.SC_NOT_FOUND)
        );
        assertThat(deleteAuthFailuresResponseNoExist.getBody(), containsString("listener not found"));

    }

    @Test
    public void testInvalidPutScenarios() throws Exception {
        setupWithRestRoles();

        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse updateAuthFailuresResponseNoBackend = rh.executePutRequest(
            "/_plugins/_security/api/authfailurelisteners/test",
            "{\"type\":\"username\",\"allowed_tries\":10,\"time_window_seconds\":3600,\"block_expiry_seconds\":600,\"max_blocked_clients\":100000,\"max_tracked_clients\":100000}",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(
            updateAuthFailuresResponseNoBackend.getBody(),
            updateAuthFailuresResponseNoBackend.getStatusCode(),
            equalTo(HttpStatus.SC_BAD_REQUEST)
        );

        RestHelper.HttpResponse updateAuthFailuresResponseNoType = rh.executePutRequest(
            "/_plugins/_security/api/authfailurelisteners/test",
            "{\"allowed_tries\":10,\"time_window_seconds\":3600,\"block_expiry_seconds\":600,\"max_blocked_clients\":100000,\"max_tracked_clients\":100000}",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(
            updateAuthFailuresResponseNoType.getBody(),
            updateAuthFailuresResponseNoType.getStatusCode(),
            equalTo(HttpStatus.SC_BAD_REQUEST)
        );

    }

    @Test
    public void testPutWithAllDefaults() throws Exception {
        setupWithRestRoles();
        rh.sendAdminCertificate = true;

        // Put a test auth failure listener
        RestHelper.HttpResponse updateAuthFailuresResponse = rh.executePutRequest(
            "/_plugins/_security/api/authfailurelisteners/test",
            "{\"type\":\"ip\"}",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(updateAuthFailuresResponse.getBody(), updateAuthFailuresResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // Get after put returns the test auth failure listener with proper defaults set
        RestHelper.HttpResponse getAuthFailuresResponseAfterPut = rh.executeGetRequest(
            "/_plugins/_security/api/authfailurelisteners",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(getAuthFailuresResponseAfterPut.getBody(), getAuthFailuresResponseAfterPut.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(
            getAuthFailuresResponseAfterPut.getBody(),
            getAuthFailuresResponseAfterPut.getBody(),
            equalTo(
                "{\"test\":{\"name\":\"test\",\"type\":\"ip\",\"ignore_hosts\":[],\"authentication_backend\":null,\"allowed_tries\":10,\"time_window_seconds\":3600,\"block_expiry_seconds\":600,\"max_blocked_clients\":100000,\"max_tracked_clients\":100000}}"
            )
        );
    }

    @Test
    public void testPutWithSomeDefaults() throws Exception {
        setupWithRestRoles();
        rh.sendAdminCertificate = true;

        // Put another test auth failure listener with some fields provided
        RestHelper.HttpResponse updateAuthFailuresResponse = rh.executePutRequest(
            "/_plugins/_security/api/authfailurelisteners/test",
            "{\"type\":\"ip\",\"allowed_tries\":88,\"time_window_seconds\":12345}",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(updateAuthFailuresResponse.getBody(), updateAuthFailuresResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // Get after put returns the test auth failure listener with proper defaults set
        RestHelper.HttpResponse getAuthFailuresResponseAfterPut = rh.executeGetRequest(
            "/_plugins/_security/api/authfailurelisteners",
            ADMIN_FULL_ACCESS_USER
        );
        assertThat(getAuthFailuresResponseAfterPut.getBody(), getAuthFailuresResponseAfterPut.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(
            getAuthFailuresResponseAfterPut.getBody(),
            getAuthFailuresResponseAfterPut.getBody(),
            equalTo(
                "{\"test\":{\"name\":\"test\",\"type\":\"ip\",\"ignore_hosts\":[],\"authentication_backend\":null,\"allowed_tries\":88,\"time_window_seconds\":12345,\"block_expiry_seconds\":600,\"max_blocked_clients\":100000,\"max_tracked_clients\":100000}}"
            )
        );
    }

}
