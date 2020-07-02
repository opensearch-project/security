package com.amazon.opendistroforelasticsearch.security.filter;

import com.amazon.opendistroforelasticsearch.security.dlic.rest.api.AbstractRestApiUnitTest;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.WhitelistingSettings;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

/**
 * Currently tests that the whitelisting functionality works correctly.
 * Uses the test/resources/restapi folder for setup.
 */
public class OpenDistroSecurityRestFilterTest extends AbstractRestApiUnitTest {

    private RestHelper.HttpResponse response;

    /**
     * admin_all_access is a user who has all permissions - essentially an admin user, not the same as superadmin.
     * superadmin is identified by a certificate that should be passed as a part of the request header.
     */
    private final Header adminCredsHeader = encodeBasicHeader("admin_all_access", "admin_all_access");
    private final Header nonAdminCredsHeader = encodeBasicHeader("sarek", "sarek");

    /**
     * Tests that whitelisted APIs can be accessed by all users.
     *
     * @throws Exception
     */
    @Test
    public void checkWhitelistedApisAreAccessible() throws Exception {

        setup();

        //ADD SOME WHITELISTED APIs
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest("_opendistro/_security/api/whitelist", "{\"whitelisting_enabled\": true, \"whitelisted_APIs\": [\"/_cat/nodes\",\"/_cat/indices\"]}", adminCredsHeader);

        log.warn("the response is:" + rh.executeGetRequest("_opendistro/_security/api/whitelist", adminCredsHeader));

        //NON ADMIN TRIES ACCESSING A WHITELISTED API - OK
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/nodes", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        //ADMIN TRIES ACCESSING A WHITELISTED API - OK
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/nodes", adminCredsHeader);
        log.warn("the second response is:" + response);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        //SUPERADMIN TRIES ACCESSING A WHITELISTED API - OK
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest("_cat/nodes", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
    }

    /**
     * Tests that non-whitelisted APIs are only accessible by superadmin
     *
     * @throws Exception
     */
    @Test
    public void checkNonWhitelistedApisAccessibleOnlyBySuperAdmin() throws Exception {
        setup();

        //ADD SOME WHITELISTED APIs - /_cat/nodes and /_cat/indices
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest("_opendistro/_security/api/whitelist", "{\"whitelisting_enabled\": true, \"whitelisted_APIs\": [\"/_cat/nodes\",\"/_cat/indices\"]}", nonAdminCredsHeader);

        //NON ADMIN TRIES ACCESSING A NON-WHITELISTED API - FORBIDDEN
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/plugins", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        //ADMIN TRIES ACCESSING A NON-WHITELISTED API - FORBIDDEN
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/plugins", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

        //SUPERADMIN TRIES ACCESSING A NON-WHITELISTED API - OK
        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest("_cat/plugins", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
    }

    /**
     * Checks that all APIs are accessible by any user when {@link WhitelistingSettings#getWhitelistingEnabled()} is false
     */
    @Test
    public void checkAllApisWhenWhitelistingNotEnabled() throws Exception {
        setup();

        //DISABLE WHITELISTING BUT ADD SOME WHITELISTED APIs - /_cat/nodes and /_cat/plugins
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest("_opendistro/_security/api/whitelist", "{\"whitelisting_enabled\": false, \"whitelisted_APIs\": [\"/_cat/nodes\",\"/_cat/indices\"]}", nonAdminCredsHeader);

        //NON-ADMIN TRIES ACCESSING 2 APIs: One in the list and one outside - OK for both (Because whitelisting is off)
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/plugins", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        response = rh.executeGetRequest("_cat/nodes", nonAdminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        //ADMIN USER TRIES ACCESSING 2 APIs: One in the list and one outside - OK for both (Because whitelisting is off)
        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_cat/plugins", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        response = rh.executeGetRequest("_cat/nodes", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));

        //SUPERADMIN TRIES ACCESSING 2 APIS - OK (would work even if whitelisting was on)

        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest("_cat/plugins", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        response = rh.executeGetRequest("_cat/nodes", adminCredsHeader);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
    }
}
