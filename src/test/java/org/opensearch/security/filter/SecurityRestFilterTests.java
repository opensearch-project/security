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

package org.opensearch.security.filter;

import org.apache.hc.core5.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.security.dlic.rest.api.AbstractRestApiUnitTest;
import org.opensearch.security.securityconf.impl.AllowlistingSettings;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Currently tests that the allowlisting functionality works correctly.
 * Uses the test/resources/restapi folder for setup.
 */
public class SecurityRestFilterTests extends AbstractRestApiUnitTest {

    private RestHelper.HttpResponse response;

    /**
     * admin_all_access is a user who has all permissions - essentially an admin user, not the same as superadmin.
     * superadmin is identified by a certificate that should be passed as a part of the request header.
     */
    private final Header adminCredsHeader = encodeBasicHeader("admin_all_access", "admin_all_access");
    private final Header nonAdminCredsHeader = encodeBasicHeader("sarek", "sarek");

    /**
     * Tests that allowlisted APIs can be accessed by all users.
     *
     * @throws Exception
     */
    @Test
    public void checkAllowlistedApisAreAccessible() throws Exception {

        setup();

        // ADD SOME ALLOWLISTED APIs
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(
            "_plugins/_security/api/allowlist",
            "{\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}",
            adminCredsHeader
        );

        log.warn("the response is:" + rh.executeGetRequest("_plugins/_security/api/allowlist", adminCredsHeader));

        // NON ADMIN TRIES ACCESSING A ALLOWLISTED API - OK
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/nodes", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // ADMIN TRIES ACCESSING A ALLOWLISTED API - OK
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/nodes", adminCredsHeader);
        log.warn("the second response is:{}", response);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // SUPERADMIN TRIES ACCESSING A ALLOWLISTED API - OK
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest("_cat/nodes", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
    }

    /**
     * Tests that non-allowlisted APIs are only accessible by superadmin
     *
     * @throws Exception
     */
    @Test
    public void checkNonAllowlistedApisAccessibleOnlyBySuperAdmin() throws Exception {
        setup();

        // ADD SOME ALLOWLISTED APIs - /_cat/nodes and /_cat/indices
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(
            "_plugins/_security/api/allowlist",
            "{\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}",
            nonAdminCredsHeader
        );

        // NON ADMIN TRIES ACCESSING A NON-ALLOWLISTED API - FORBIDDEN
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/plugins", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        // ADMIN TRIES ACCESSING A NON-ALLOWLISTED API - FORBIDDEN
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/plugins", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        // SUPERADMIN TRIES ACCESSING A NON-ALLOWLISTED API - OK
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest("_cat/plugins", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
    }

    /**
     * Checks that all APIs are accessible by any user when {@link AllowlistingSettings#getEnabled()} is false
     */
    @Test
    public void checkAllApisWhenAllowlistingNotEnabled() throws Exception {
        setup();

        // DISABLE ALLOWLISTED BUT ADD SOME ALLOWLISTED APIs - /_cat/nodes and /_cat/plugins
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(
            "_plugins/_security/api/allowlist",
            "{\"enabled\": false, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}",
            nonAdminCredsHeader
        );

        // NON-ADMIN TRIES ACCESSING 2 APIs: One in the list and one outside - OK for both (Because allowlisting is off)
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/plugins", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        response = rh.executeGetRequest("_cat/nodes", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // ADMIN USER TRIES ACCESSING 2 APIs: One in the list and one outside - OK for both (Because allowlisting is off)
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/plugins", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        response = rh.executeGetRequest("_cat/nodes", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // SUPERADMIN TRIES ACCESSING 2 APIS - OK (would work even if allowlisting was on)

        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest("_cat/plugins", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        response = rh.executeGetRequest("_cat/nodes", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
    }

    /**
     * Checks that request method specific allowlisting works properly.
     * Checks that if only GET /_cluster/settings is allowlisted, then:
     * non admin user can access GET /_cluster/settings, but not PUT /_cluster/settings
     * admin user can access GET /_cluster/settings, but not PUT /_cluster/settings
     * SuperAdmin can access GET /_cluster/settings and PUT /_cluster/settings
     *
     */
    @Test
    public void checkSpecificRequestMethodAllowlisting() throws Exception {
        setup();

        // ALLOWLIST GET /_cluster/settings
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(
            "_plugins/_security/api/allowlist",
            "{\"enabled\": true, \"requests\": {\"/_cluster/settings\": [\"GET\"]}}",
            nonAdminCredsHeader
        );

        // NON-ADMIN TRIES ACCESSING GET - OK, PUT - FORBIDDEN

        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cluster/settings", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        response = rh.executePutRequest(
            "_cluster/settings",
            "{\"persistent\": { }, \"transient\": {\"indices.recovery.max_bytes_per_sec\": \"15mb\" }}",
            nonAdminCredsHeader
        );
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        // ADMIN USER TRIES ACCESSING GET - OK, PUT - FORBIDDEN
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cluster/settings", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        response = rh.executePutRequest(
            "_cluster/settings",
            "{\"persistent\": { }, \"transient\": {\"indices.recovery.max_bytes_per_sec\": \"15mb\" }}",
            adminCredsHeader
        );
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        // SUPERADMIN TRIES ACCESSING GET - OK, PUT - OK
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest("_cluster/settings", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        response = rh.executePutRequest(
            "_cluster/settings",
            "{\"persistent\": { }, \"transient\": {\"indices.recovery.max_bytes_per_sec\": \"15mb\" }}",
            adminCredsHeader
        );
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
    }

    /**
     * Tests that a allowlisted API with an extra '/' does not cause an issue
     * i.e if only GET /_cluster/settings/ is allowlisted, then:
     * GET /_cluster/settings/  - OK
     * GET /_cluster/settings - OK
     * PUT /_cluster/settings/  - FORBIDDEN
     * PUT /_cluster/settings - FORBIDDEN
     * @throws Exception
     */
    @Test
    public void testAllowlistedApiWithExtraSlash() throws Exception {
        setup();

        // ALLOWLIST GET /_cluster/settings/ - extra / in the request
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(
            "_plugins/_security/api/allowlist",
            "{\"enabled\": true, \"requests\": {\"/_cluster/settings/\": [\"GET\"]}}",
            nonAdminCredsHeader
        );

        // NON ADMIN ACCESS GET /_cluster/settings/ - OK
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cluster/settings/", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // NON ADMIN ACCESS GET /_cluster/settings - OK
        response = rh.executeGetRequest("_cluster/settings", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // NON ADMIN ACCESS PUT /_cluster/settings/ - FORBIDDEN
        response = rh.executePutRequest(
            "_cluster/settings/",
            "{\"persistent\": { }, \"transient\": {\"indices.recovery.max_bytes_per_sec\": \"15mb\" }}",
            adminCredsHeader
        );
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        // NON ADMIN ACCESS PUT /_cluster/settings - FORBIDDEN
        response = rh.executePutRequest(
            "_cluster/settings",
            "{\"persistent\": { }, \"transient\": {\"indices.recovery.max_bytes_per_sec\": \"15mb\" }}",
            adminCredsHeader
        );
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

    }

    /**
     * Tests that a allowlisted API without an extra '/' does not cause an issue
     * i.e if only GET /_cluster/settings is allowlisted, then:
     * GET /_cluster/settings/ - OK
     * GET /_cluster/settings - OK
     * PUT /_cluster/settings/ - FORBIDDEN
     * PUT /_cluster/settings - FORBIDDEN
     * @throws Exception
     */
    @Test
    public void testAllowlistedApiWithoutExtraSlash() throws Exception {
        setup();

        // ALLOWLIST GET /_cluster/settings (no extra / in request)
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(
            "_plugins/_security/api/allowlist",
            "{\"enabled\": true, \"requests\": {\"/_cluster/settings\": [\"GET\"]}}",
            nonAdminCredsHeader
        );

        // NON ADMIN ACCESS GET /_cluster/settings/ - OK
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cluster/settings/", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // NON ADMIN ACCESS GET /_cluster/settings - OK
        response = rh.executeGetRequest("_cluster/settings", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // NON ADMIN ACCESS PUT /_cluster/settings/ - FORBIDDEN
        response = rh.executePutRequest(
            "_cluster/settings/",
            "{\"persistent\": { }, \"transient\": {\"indices.recovery.max_bytes_per_sec\": \"15mb\" }}",
            adminCredsHeader
        );
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        // NON ADMIN ACCESS PUT /_cluster/settings - FORBIDDEN
        response = rh.executePutRequest(
            "_cluster/settings",
            "{\"persistent\": { }, \"transient\": {\"indices.recovery.max_bytes_per_sec\": \"15mb\" }}",
            adminCredsHeader
        );
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
    }

    /**
     * Tests that when has_permission_check param is absent;
     * the normal request flow is executed.
     *
     * @throws Exception
     */
    @Test
    public void testWithoutHasPermissionCheckParam() throws Exception {
        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(
            "_plugins/_security/api/allowlist",
            "{\"enabled\": true, \"requests\": {\"/_cluster/health\": [\"GET\"]}}",
            nonAdminCredsHeader
        );

        // No has_permission_check param behaves like normal flow (no simulation fields)
        rh.sendAdminCertificate = false;
        assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertFalse(response.getBody().contains("\"accessAllowed\""));
        assertFalse(response.getBody().contains("\"missingPrivileges\""));

    }

    /**
     * Tests that the has_permission_check param works correctly.
     * When has_permission_check=true is added to a request, returns
     * whether the request would be allowed or Denied, without actually executing the request.
     *
     * @throws Exception
     */
    @Test
    public void testHasPermissionCheckParam_AccessAllowedCase() throws Exception {
        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest("_cluster/health?has_permission_check=true", nonAdminCredsHeader);
        rh.sendAdminCertificate = false;
        // user has permissions to GET /_cluster/health response accessAllowed:true
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertTrue(response.getBody().contains("\"accessAllowed\":true"));
        assertTrue(response.getBody().contains("\"missingPrivileges\":[]"));

        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(
            "_plugins/_security/api/allowlist",
            "{\"enabled\": true, \"requests\": {\"/_search?has_permission_check=false\": [\"GET\"]}}",
            nonAdminCredsHeader
        );
        // has_permission_check=false (normal execution flow) no simulation fields in response
        rh.sendAdminCertificate = false;
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertFalse(response.getBody().contains("\"accessAllowed\":"));
        assertFalse(response.getBody().contains("\"missingPrivileges\":"));

    }

    @Test
    public void testHasPermissionCheckParam_AccessNotAllowedCase() throws Exception {
        setup();

        // Create a new user with no permissions
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        String createUserBody = "{" + "\"password\": \"test-pass\"," + "\"backend_roles\": []" + "}";

        response = rh.executePutRequest("_plugins/_security/api/internalusers/test_user", createUserBody, adminCredsHeader);
        Header testUserHeader = encodeBasicHeader("test_user", "test-pass");
        rh.sendAdminCertificate = false;

        // test_user has no permissions to GET /_cluster/health response accessAllowed:false
        response = rh.executeGetRequest("_cluster/health?has_permission_check=true", testUserHeader);
        assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertTrue(response.getBody().contains("\"accessAllowed\":false"));
        assertTrue(response.getBody().contains("\"missingPrivileges\":[\"cluster:monitor/health\"]"));

    }

}
