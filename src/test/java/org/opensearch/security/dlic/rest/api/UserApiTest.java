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

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.PasswordValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.user.UserService;

import org.passay.CharacterCharacteristicsRule;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.PasswordData;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.dlic.rest.api.InternalUsersApiAction.RESTRICTED_FROM_USERNAME;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.junit.Assert.assertNotEquals;

public class UserApiTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    final int USER_SETTING_SIZE = 140; // Lines per account entry * number of accounts

    private static final String ENABLED_SERVICE_ACCOUNT_BODY = "{"
        + " \"attributes\": { \"service\": \"true\", "
        + " \"enabled   \": \"true\"}"
        + " }\n";

    private static final String DISABLED_SERVICE_ACCOUNT_BODY = "{"
        + " \"attributes\": { \"service\": \"true\", "
        + "\"enabled\": \"false\"}"
        + " }\n";
    private static final String ENABLED_NOT_SERVICE_ACCOUNT_BODY = "{"
        + " \"attributes\": { \"service\": \"false\", "
        + "\"enabled\": \"true\"}"
        + " }\n";
    private static final String PASSWORD_SERVICE = "{ \"password\" : \"test\","
        + " \"attributes\": { \"service\": \"true\", "
        + "\"enabled\": \"true\"}"
        + " }\n";
    private static final String HASH_SERVICE = "{ \"owner\" : \"test_owner\","
        + " \"attributes\": { \"service\": \"true\", "
        + "\"enabled\": \"true\"}"
        + " }\n";
    private static final String PASSWORD_HASH_SERVICE = "{ \"password\" : \"test\", \"hash\" : \"123\","
        + " \"attributes\": { \"service\": \"true\", "
        + "\"enabled\": \"true\"}"
        + " }\n";

    public UserApiTest() {
        ENDPOINT = getEndpointPrefix() + "/api";
    }

    @Test
    public void testSecurityRoles() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration, 6 users
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/" + CType.INTERNALUSERS.toLCString());
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(USER_SETTING_SIZE, settings.size());
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/newuser\", \"value\": {\"password\": \"fair password for the user\", \"opendistro_security_roles\": [\"opendistro_security_all_access\"] } }]",
            new Header[0]
        );
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(ENDPOINT + "/internalusers/newuser", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"opendistro_security_roles\":[\"opendistro_security_all_access\"]"));

        checkGeneralAccess(HttpStatus.SC_OK, "newuser", "fair password for the user");
    }

    @Test
    public void testParallelPutRequests() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        HttpResponse[] responses = executeMultipleAsyncPutRequest(
            10,
            ENDPOINT + "/internalusers/test1",
            "{\"password\":\"test1test1test1test1test1test1\"}"
        );
        boolean created = false;
        for (HttpResponse response : responses) {
            int sc = response.getStatusCode();
            switch (sc) {
                case HttpStatus.SC_CREATED:
                    Assert.assertFalse(created);
                    created = true;
                    break;
                case HttpStatus.SC_OK:
                    break;
                default:
                    Assert.assertEquals(HttpStatus.SC_CONFLICT, sc);
                    break;
            }
        }
        deleteUser("test1");
    }

    private HttpResponse[] executeMultipleAsyncPutRequest(final int numOfRequests, final String request, String body) throws Exception {
        final ExecutorService executorService = Executors.newFixedThreadPool(numOfRequests);
        try {
            List<Future<HttpResponse>> futures = new ArrayList<>(numOfRequests);
            for (int i = 0; i < numOfRequests; i++) {
                futures.add(executorService.submit(() -> rh.executePutRequest(request, body)));
            }
            return futures.stream().map(this::from).toArray(HttpResponse[]::new);
        } finally {
            executorService.shutdown();
        }
    }

    private HttpResponse from(Future<HttpResponse> future) {
        try {
            return future.get();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testUserFilters() throws Exception {
        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        final int SERVICE_ACCOUNTS_IN_SETTINGS = 1;
        final int INTERNAL_ACCOUNTS_IN_SETTINGS = 20;
        final String serviceAccountName = "JohnDoeService";
        HttpResponse response;

        response = rh.executeGetRequest(ENDPOINT + "/internalusers?filterBy=internal");

        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        JsonNode list = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(INTERNAL_ACCOUNTS_IN_SETTINGS, list.size());

        response = rh.executeGetRequest(ENDPOINT + "/internalusers?filterBy=service");
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        list = DefaultObjectMapper.readTree(response.getBody());
        assertThat(list, Matchers.emptyIterable());

        response = rh.executePutRequest(ENDPOINT + "/internalusers/" + serviceAccountName, ENABLED_SERVICE_ACCOUNT_BODY);

        // repeat assertions after adding the service account

        response = rh.executeGetRequest(ENDPOINT + "/internalusers?filterBy=internal");

        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        list = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(INTERNAL_ACCOUNTS_IN_SETTINGS, list.size());

        response = rh.executeGetRequest(ENDPOINT + "/internalusers?filterBy=service");
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        list = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(SERVICE_ACCOUNTS_IN_SETTINGS, list.size());
        assertThat(response.findValueInJson(serviceAccountName + ".attributes.service"), containsString("true"));

        response = rh.executeGetRequest(ENDPOINT + "/internalusers?filterBy=ssas");
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        list = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(SERVICE_ACCOUNTS_IN_SETTINGS + INTERNAL_ACCOUNTS_IN_SETTINGS, list.size());

        response = rh.executeGetRequest(ENDPOINT + "/internalusers?wrongparameter=jhondoe");
        Assert.assertEquals(response.getBody(), HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/internalusers", "{sample:value");
        Assert.assertEquals(response.getBody(), HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
    }

    @Test
    public void testUserApi() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/" + CType.INTERNALUSERS.toLCString());
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(USER_SETTING_SIZE, settings.size());
        verifyGet();
        verifyPut();
        verifyPatch(true);
        // create index first
        setupStarfleetIndex();
        verifyRoles(true);
    }

    private void verifyGet(final Header... header) throws Exception {
        // --- GET
        // GET, user admin, exists
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", header);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(7, settings.size());
        // hash must be filtered
        Assert.assertEquals("", settings.get("admin.hash"));

        // GET, user does not exist
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/nothinghthere", header);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // GET, new URL endpoint in security
        response = rh.executeGetRequest(ENDPOINT + "/user/", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // GET, new URL endpoint in security
        response = rh.executeGetRequest(ENDPOINT + "/user", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    private void verifyPut(final Header... header) throws Exception {
        // -- PUT
        // no username given
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/internalusers/", "{\"hash\": \"123\"}", header);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        // Faulty JSON payload
        response = rh.executePutRequest(ENDPOINT + "/internalusers/nagilum", "{some: \"thing\" asd  other: \"thing\"}", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("reason"), RequestContentValidator.ValidationError.BODY_NOT_PARSEABLE.message());

        // Missing quotes in JSON - parseable in 6.x, but wrong config keys
        response = rh.executePutRequest(ENDPOINT + "/internalusers/nagilum", "{some: \"thing\", other: \"thing\"}", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        // JK: this should be "Could not parse content of request." because JSON is truly invalid
        // Assert.assertEquals(settings.get("reason"), ValidationError.INVALID_CONFIGURATION.message());
        // Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("some"));
        // Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("other"));

        // Get hidden role
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/hide", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hidden\":true"));

        // Associating with hidden role is allowed (for superadmin)
        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/test",
            "{ \"opendistro_security_roles\": " + "[\"opendistro_security_hidden\"]}",
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // Associating with reserved role is allowed (for superadmin)
        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/test",
            "{ \"opendistro_security_roles\": [\"opendistro_security_reserved\"], " + "\"hash\": \"123\"}",
            header
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // Associating with non-existent role is not allowed
        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/nagilum",
            "{ \"opendistro_security_roles\": [\"non_existent\"]}",
            header
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("message"), "role 'non_existent' not found.");

        // Wrong config keys
        response = rh.executePutRequest(ENDPOINT + "/internalusers/nagilum", "{\"some\": \"thing\", \"other\": \"thing\"}", header);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("reason"), RequestContentValidator.ValidationError.INVALID_CONFIGURATION.message());
        Assert.assertEquals(settings.get("reason"), RequestContentValidator.ValidationError.INVALID_CONFIGURATION.message());
        Assert.assertTrue(settings.get(RequestContentValidator.INVALID_KEYS_KEY + ".keys").contains("some"));
        Assert.assertTrue(settings.get(RequestContentValidator.INVALID_KEYS_KEY + ".keys").contains("other"));

    }

    private void verifyPatch(final boolean sendAdminCert, Header... restAdminHeader) throws Exception {
        // -- PATCH
        // PATCH on non-existing resource
        rh.sendAdminCertificate = sendAdminCert;
        HttpResponse response = rh.executePatchRequest(
            ENDPOINT + "/internalusers/imnothere",
            "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]",
            restAdminHeader
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH read only resource, must be forbidden,
        // but SuperAdmin can PATCH read-only resource
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers/sarek",
            "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]",
            restAdminHeader
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH hidden resource, must be not found, can be found for super admin
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers/q",
            "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]",
            restAdminHeader
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers/test",
            "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]",
            restAdminHeader
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH password
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers/test",
            "[{ \"op\": \"add\", \"path\": \"/password\", \"value\": \"neu password 42\" }]",
            restAdminHeader
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/test", restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertFalse(settings.hasValue("test.password"));
        Assert.assertTrue(settings.hasValue("test.hash"));

        // -- PATCH on whole config resource
        // PATCH on non-existing resource
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/imnothere/a\", \"value\": [ \"foo\", \"bar\" ] }]",
            restAdminHeader
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH read only resource, must be forbidden,
        // but SuperAdmin can PATCH read only resouce
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/sarek/description\", \"value\": \"foo\" }]",
            restAdminHeader
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        rh.sendAdminCertificate = false;
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/sarek/a\", \"value\": [ \"foo\", \"bar\" ] }]"
        );
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // PATCH hidden resource, must be bad request
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/q/a\", \"value\": [ \"foo\", \"bar\" ] }]",
            restAdminHeader
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/test/hidden\", \"value\": true }]",
            restAdminHeader
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/bulknew1\", \"value\": {\"password\": \"bla bla bla password 42\", \"backend_roles\": [\"vulcan\"] } }]",
            restAdminHeader
        );
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/bulknew1", restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertFalse(settings.hasValue("bulknew1.password"));
        Assert.assertTrue(settings.hasValue("bulknew1.hash"));
        List<String> roles = settings.getAsList("bulknew1.backend_roles");
        Assert.assertEquals(1, roles.size());
        Assert.assertTrue(roles.contains("vulcan"));

        // add user with correct setting. User is in role "opendistro_security_all_access"

        // check access not allowed
        checkGeneralAccess(HttpStatus.SC_UNAUTHORIZED, "nagilum", "nagilum");

        // add/update user, user is read only, forbidden
        // SuperAdmin can add read only users
        rh.sendAdminCertificate = sendAdminCert;
        addUserWithHash("sarek", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m", HttpStatus.SC_OK);

        // add/update user, user is hidden, forbidden, allowed for super admin
        rh.sendAdminCertificate = sendAdminCert;
        addUserWithHash("q", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m", HttpStatus.SC_OK);

        // add users
        rh.sendAdminCertificate = sendAdminCert;
        addUserWithHash("nagilum", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m", HttpStatus.SC_CREATED);

        // Add enabled service account then get it
        response = rh.executePutRequest(ENDPOINT + "/internalusers/happyServiceLive", ENABLED_SERVICE_ACCOUNT_BODY, restAdminHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/happyServiceLive", restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // Add disabled service account
        response = rh.executePutRequest(ENDPOINT + "/internalusers/happyServiceDead", DISABLED_SERVICE_ACCOUNT_BODY, restAdminHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());

        // Add service account with password -- Should Fail
        response = rh.executePutRequest(ENDPOINT + "/internalusers/passwordService", PASSWORD_SERVICE, restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // Add service with hash -- should fail
        response = rh.executePutRequest(ENDPOINT + "/internalusers/hashService", HASH_SERVICE, restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // Add Service account with password & Hash -- should fail
        response = rh.executePutRequest(ENDPOINT + "/internalusers/passwordHashService", PASSWORD_HASH_SERVICE, restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // access must be allowed now
        checkGeneralAccess(HttpStatus.SC_OK, "nagilum", "nagilum");

        // try remove user, no username
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers", restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        // try remove user, nonexisting user
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/picard", restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // try remove readonly user
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/sarek", restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // try remove hidden user, allowed for super admin
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/q", restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("'q' deleted."));
        // now really remove user
        deleteUser("nagilum");

        // Access must be forbidden now
        rh.sendAdminCertificate = false;
        checkGeneralAccess(HttpStatus.SC_UNAUTHORIZED, "nagilum", "nagilum");

        // use password instead of hash
        rh.sendAdminCertificate = sendAdminCert;
        addUserWithPassword("nagilum", "correctpassword", HttpStatus.SC_CREATED);

        rh.sendAdminCertificate = false;
        checkGeneralAccess(HttpStatus.SC_UNAUTHORIZED, "nagilum", "wrongpassword");
        checkGeneralAccess(HttpStatus.SC_OK, "nagilum", "correctpassword");

        deleteUser("nagilum");

        // Check unchanged password functionality
        rh.sendAdminCertificate = sendAdminCert;

        // new user, password or hash is mandatory
        addUserWithoutPasswordOrHash("nagilum", new String[] { "starfleet" }, HttpStatus.SC_BAD_REQUEST);
        // new user, add hash
        addUserWithHash("nagilum", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m", HttpStatus.SC_CREATED);
        // update user, do not specify hash or password, hash must remain the same
        addUserWithoutPasswordOrHash("nagilum", new String[] { "starfleet" }, HttpStatus.SC_OK);
        // get user, check hash, must be untouched
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/nagilum", restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertTrue(settings.get("nagilum.hash").equals(""));
    }

    private void verifyAuthToken(final boolean sendAdminCert, Header... restAdminHeader) throws Exception {

        // Add enabled service account then generate auth token

        rh.sendAdminCertificate = sendAdminCert;
        HttpResponse response = rh.executePutRequest(
            ENDPOINT + "/internalusers/happyServiceLive",
            ENABLED_SERVICE_ACCOUNT_BODY,
            restAdminHeader
        );
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/happyServiceLive", restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePostRequest(
            ENDPOINT + "/internalusers/happyServiceLive/authtoken",
            ENABLED_SERVICE_ACCOUNT_BODY,
            restAdminHeader
        );
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());
        String tokenFromResponse = response.getBody();
        byte[] decodedResponse = Base64.getUrlDecoder().decode(tokenFromResponse);
        String[] decodedResponseString = new String(decodedResponse).split(":", 2);
        String username = decodedResponseString[0];
        String password = decodedResponseString[1];
        Assert.assertEquals("Username is: " + username, username, "happyServiceLive");

        // Add disabled service account then try to get its auth token
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePutRequest(ENDPOINT + "/internalusers/happyServiceDead", DISABLED_SERVICE_ACCOUNT_BODY, restAdminHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());

        response = rh.executePostRequest(
            ENDPOINT + "/internalusers/happyServiceDead/authtoken",
            ENABLED_SERVICE_ACCOUNT_BODY,
            restAdminHeader
        );
        Assert.assertEquals(response.getBody(), HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // Add enabled non-service account
        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePutRequest(ENDPOINT + "/internalusers/user_is_owner_1", ENABLED_NOT_SERVICE_ACCOUNT_BODY, restAdminHeader);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        response = rh.executePostRequest(
            ENDPOINT + "/internalusers/user_is_owner_1/authtoken",
            ENABLED_SERVICE_ACCOUNT_BODY,
            restAdminHeader
        );
        Assert.assertEquals(response.getBody(), HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

    }

    private void verifyRoles(final boolean sendAdminCert, Header... header) throws Exception {

        // wrong datatypes in roles file
        rh.sendAdminCertificate = sendAdminCert;
        HttpResponse response = rh.executePutRequest(
            ENDPOINT + "/internalusers/picard",
            FileHelper.loadFile("restapi/users_wrong_datatypes.json"),
            header
        );
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.WRONG_DATATYPE.message(), settings.get("reason"));
        Assert.assertTrue(settings.get("backend_roles").equals("Array expected"));
        rh.sendAdminCertificate = false;

        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/picard",
            FileHelper.loadFile("restapi/users_wrong_datatypes.json"),
            header
        );
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.WRONG_DATATYPE.message(), settings.get("reason"));
        Assert.assertTrue(settings.get("backend_roles").equals("Array expected"));
        rh.sendAdminCertificate = false;

        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/picard",
            FileHelper.loadFile("restapi/users_wrong_datatypes2.json"),
            header
        );
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.WRONG_DATATYPE.message(), settings.get("reason"));
        Assert.assertTrue(settings.get("password").equals("String expected"));
        Assert.assertTrue(settings.get("backend_roles") == null);
        rh.sendAdminCertificate = false;

        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/picard",
            FileHelper.loadFile("restapi/users_wrong_datatypes3.json"),
            header
        );
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.WRONG_DATATYPE.message(), settings.get("reason"));
        Assert.assertTrue(settings.get("backend_roles").equals("Array expected"));
        rh.sendAdminCertificate = false;

        // use backendroles when creating user. User picard does not exist in
        // the internal user DB
        // and is also not assigned to any role by username
        addUserWithPassword("picard", "picardpicardpicardpicardpicard", HttpStatus.SC_CREATED);
        // changed in ES5, you now need cluster:monitor/main which pucard does not have
        checkGeneralAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicardpicard");

        // check read access to starfleet index and _doc type, must fail
        checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicardpicard", "sf", "_doc", 0);

        // overwrite user picard, and give him role "starfleet".
        addUserWithPassword("picard", "picardpicardpicardpicardpicard", new String[] { "starfleet" }, HttpStatus.SC_OK);

        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picardpicardpicardpicardpicard", "sf", "_doc", 1);

        // overwrite user picard, and give him role "starfleet" plus "captains. Now
        // document can be created.
        addUserWithPassword("picard", "picardpicardpicardpicardpicard", new String[] { "starfleet", "captains" }, HttpStatus.SC_OK);
        checkReadAccess(HttpStatus.SC_OK, "picard", "picardpicardpicardpicardpicard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_CREATED, "picard", "picardpicardpicardpicardpicard", "sf", "_doc", 1);

        rh.sendAdminCertificate = sendAdminCert;
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/picard", header);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals("", settings.get("picard.hash"));
        List<String> roles = settings.getAsList("picard.backend_roles");
        Assert.assertNotNull(roles);
        Assert.assertEquals(2, roles.size());
        Assert.assertTrue(roles.contains("starfleet"));
        Assert.assertTrue(roles.contains("captains"));

        addUserWithPassword("some_additional_user", "$1aAAAAAAAAC", HttpStatus.SC_CREATED);
        addUserWithPassword("abc", "abcabcabcabc42", HttpStatus.SC_CREATED);

        // check tabs in json
        response = rh.executePutRequest(ENDPOINT + "/internalusers/userwithtabs", "\t{\"hash\": \t \"123\"\t}  ", header);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());
    }

    @Test
    public void testUserApiWithRestAdminPermissions() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        rh.sendAdminCertificate = false;
        final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
        // initial configuration
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/" + CType.INTERNALUSERS.toLCString(), restApiAdminHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(USER_SETTING_SIZE, settings.size());
        verifyGet(restApiAdminHeader);
        verifyPut(restApiAdminHeader);
        verifyPatch(false, restApiAdminHeader);
        // create index first
        setupStarfleetIndex();
        verifyRoles(false, restApiAdminHeader);
    }

    @Test
    public void testUserApiWithRestInternalUsersAdminPermissions() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        rh.sendAdminCertificate = false;
        final Header restApiInternalUsersAdminHeader = encodeBasicHeader("rest_api_admin_internalusers", "rest_api_admin_internalusers");
        // initial configuration
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/" + CType.INTERNALUSERS.toLCString(), restApiInternalUsersAdminHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(USER_SETTING_SIZE, settings.size());
        verifyGet(restApiInternalUsersAdminHeader);
        verifyPut(restApiInternalUsersAdminHeader);
        verifyPatch(false, restApiInternalUsersAdminHeader);
        // create index first
        setupStarfleetIndex();
        verifyRoles(false, restApiInternalUsersAdminHeader);
    }

    @Test
    public void testRegExpPasswordRules() throws Exception {
        Settings nodeSettings = Settings.builder()
            .put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, "xxx")
            .put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, "(?=.*[A-Z])(?=.*[^a-zA-Z\\\\d])(?=.*[0-9])(?=.*[a-z]).{8,}")
            .put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH, PasswordValidator.ScoreStrength.FAIR.name())
            .build();

        setup(nodeSettings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration, 6 users
        HttpResponse response = rh.executeGetRequest("_plugins/_security/api/" + CType.INTERNALUSERS.toLCString());
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(USER_SETTING_SIZE, settings.size());

        verifyCouldNotCreatePasswords(HttpStatus.SC_BAD_REQUEST);
        verifyCanCreatePasswords();
        verifySimilarity(RequestContentValidator.ValidationError.SIMILAR_PASSWORD.message());

        addUserWithPasswordAndHash("empty_password", "", "$%^123", HttpStatus.SC_BAD_REQUEST);
        addUserWithPasswordAndHash("null_password", null, "$%^123", HttpStatus.SC_BAD_REQUEST);

        response = rh.executeGetRequest(PLUGINS_PREFIX + "/api/internalusers/nothinghthere?pretty", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("NOT_FOUND"));
    }

    private void verifyCouldNotCreatePasswords(final int expectedStatus) throws Exception {
        addUserWithPassword("tooshoort", "", expectedStatus);
        addUserWithPassword("tooshoort", "123", expectedStatus);
        addUserWithPassword("tooshoort", "1234567", expectedStatus);
        addUserWithPassword("tooshoort", "1Aa%", expectedStatus);
        addUserWithPassword("no-nonnumeric", "123456789", expectedStatus);
        addUserWithPassword("no-uppercase", "a123456789", expectedStatus);
        addUserWithPassword("no-lowercase", "A123456789", expectedStatus);
        addUserWithPassword("empty_password_no_hash", "", expectedStatus);
        HttpResponse response = rh.executePatchRequest(
            PLUGINS_PREFIX + "/api/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/ok4\", \"value\": {\"password\": \"bla\", \"backend_roles\": [\"vulcan\"] } }]",
            new Header[0]
        );
        Assert.assertEquals(response.getBody(), expectedStatus, response.getStatusCode());
        response = rh.executePatchRequest(
            PLUGINS_PREFIX + "/api/internalusers",
            "[{ \"op\": \"replace\", \"path\": \"/ok4\", \"value\": {\"password\": \"bla\", \"backend_roles\": [\"vulcan\"] } }]",
            new Header[0]
        );
        Assert.assertEquals(response.getBody(), expectedStatus, response.getStatusCode());
        addUserWithPassword("ok4", "123", expectedStatus);

        // its not allowed to use the username as password (case insensitive)
        response = rh.executePatchRequest(
            PLUGINS_PREFIX + "/api/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/$1aAAAAAAAAB\", \"value\": {\"password\": \"$1aAAAAAAAAB\", \"backend_roles\": [\"vulcan\"] } }]",
            new Header[0]
        );
        Assert.assertEquals(response.getBody(), expectedStatus, response.getStatusCode());
        addUserWithPassword("$1aAAAAAAAAC", "$1aAAAAAAAAC", expectedStatus);
        addUserWithPassword("$1aAAAAAAAac", "$1aAAAAAAAAC", expectedStatus);
        addUserWithPassword(URLEncoder.encode("$1aAAAAAAAac%", "UTF-8"), "$1aAAAAAAAAC%", expectedStatus);
        addUserWithPassword(
            URLEncoder.encode("$1aAAAAAAAac%!=\"/\\;:test&~@^", "UTF-8").replace("+", "%2B"),
            "$1aAAAAAAAac%!=\\\"/\\\\;:test&~@^",
            expectedStatus
        );
        addUserWithPassword(
            URLEncoder.encode("$1aAAAAAAAac%!=\"/\\;: test&", "UTF-8"),
            "$1aAAAAAAAac%!=\\\"/\\\\;: test&123",
            expectedStatus
        );
        String patchPayload = "[ "
            + "{ \"op\": \"add\", \"path\": \"/testuser1\",  \"value\": { \"password\": \"$aA123456789\", \"backend_roles\": [\"testrole1\"] } },"
            + "{ \"op\": \"add\", \"path\": \"/testuser2\",  \"value\": { \"password\": \"testpassword2\", \"backend_roles\": [\"testrole2\"] } }"
            + "]";

        response = rh.executePatchRequest(
            PLUGINS_PREFIX + "/api/internalusers",
            patchPayload,
            new BasicHeader("Content-Type", "application/json")
        );
        Assert.assertEquals(expectedStatus, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("error"));
        Assert.assertTrue(response.getBody().contains("xxx"));

        response = rh.executePutRequest(
            PLUGINS_PREFIX + "/api/internalusers/ok1",
            "{\"backend_roles\":[\"my-backend-role\"],\"attributes\":{},\"password\":\"\"}",
            new Header[0]
        );
        Assert.assertEquals(expectedStatus, response.getStatusCode());

        response = rh.executePutRequest(
            PLUGINS_PREFIX + "/api/internalusers/ok1",
            "{\"backend_roles\":[\"my-backend-role\"],\"attributes\":{},\"password\":\"bla\"}",
            new Header[0]
        );
        Assert.assertEquals(expectedStatus, response.getStatusCode());
    }

    private void verifyCanCreatePasswords() throws Exception {
        addUserWithPassword("ok1", "a%A123456789", HttpStatus.SC_CREATED);
        addUserWithPassword("ok2", "$aA123456789", HttpStatus.SC_CREATED);
        addUserWithPassword("ok3", "$Aa123456789", HttpStatus.SC_CREATED);
        addUserWithPassword("ok4", "$1aAAAAAAAAA", HttpStatus.SC_CREATED);
        addUserWithPassword("ok4", "$1aAAAAAAAAC", HttpStatus.SC_OK);
        HttpResponse response = rh.executePatchRequest(
            PLUGINS_PREFIX + "/api/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/ok4\", \"value\": {\"password\": \"$1aAAAAAAAAB\", \"backend_roles\": [\"vulcan\"] } }]",
            new Header[0]
        );
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executePutRequest(
            PLUGINS_PREFIX + "/api/internalusers/ok1",
            "{\"backend_roles\":[\"my-backend-role\"],\"attributes\":{},\"password\":\"Admin_123\"}",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(
            PLUGINS_PREFIX + "/api/internalusers/ok1",
            "{\"backend_roles\":[\"my-backend-role\"],\"attributes\":{}}",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

    }

    private void verifySimilarity(final String expectedMessage) throws Exception {
        addUserWithPassword("some_user_name", "H3235,cc,some_User_Name", HttpStatus.SC_BAD_REQUEST, expectedMessage);
    }

    @Test
    public void testScoreBasedPasswordRules() throws Exception {

        Settings nodeSettings = Settings.builder().put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, 9).build();

        setup(nodeSettings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration, 6 users
        HttpResponse response = rh.executeGetRequest("_plugins/_security/api/" + CType.INTERNALUSERS.toLCString());
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(USER_SETTING_SIZE, settings.size());

        addUserWithPassword(
            "admin",
            "password89",
            HttpStatus.SC_BAD_REQUEST,
            RequestContentValidator.ValidationError.WEAK_PASSWORD.message()
        );
        addUserWithPassword(
            "admin",
            "A123456789",
            HttpStatus.SC_BAD_REQUEST,
            RequestContentValidator.ValidationError.WEAK_PASSWORD.message()
        );

        addUserWithPassword(
            "admin",
            "pas",
            HttpStatus.SC_BAD_REQUEST,
            RequestContentValidator.ValidationError.INVALID_PASSWORD_TOO_SHORT.message()
        );

        verifySimilarity(RequestContentValidator.ValidationError.SIMILAR_PASSWORD.message());

        addUserWithPassword("some_user_name", "ASSDsadwe324wadaasdadqwe", HttpStatus.SC_CREATED);
    }

    @Test
    public void testUserApiWithDots() throws Exception {
        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration, 6 users
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/" + CType.INTERNALUSERS.toLCString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(USER_SETTING_SIZE, settings.size());

        addUserWithPassword(".my.dotuser0", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m", HttpStatus.SC_CREATED);

        addUserWithPassword(".my.dot.user0", "12345678Sd", HttpStatus.SC_CREATED);

        addUserWithHash(".my.dotuser1", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m", HttpStatus.SC_CREATED);

        addUserWithPassword(".my.dot.user2", "12345678Sd", HttpStatus.SC_CREATED);

    }

    @Test
    public void testUserApiNoPasswordChange() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration, 5 users
        HttpResponse response;

        addUserWithHash("user1", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m", HttpStatus.SC_CREATED);

        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/user1",
            "{\"hash\":\"$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m\",\"password\":\"\",\"backend_roles\":[\"admin\",\"rolea\"]}"
        );
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/user1",
            "{\"hash\":\"$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m\",\"password\":\"Admin_123\",\"backend_roles\":[\"admin\",\"rolea\"]}"
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(ENDPOINT + "/internalusers/user1");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        addUserWithHash("user2", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m", HttpStatus.SC_CREATED);

        response = rh.executePutRequest(ENDPOINT + "/internalusers/user2", "{\"password\":\"\",\"backend_roles\":[\"admin\",\"rolex\"]}");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/user2",
            "{\"password\":\"Admin_123\",\"backend_roles\":[\"admin\",\"rolex\"]}"
        );
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(ENDPOINT + "/internalusers/user2");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testUserApiForNonSuperAdmin() throws Exception {

        setupWithRestRoles();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;
        rh.sendHTTPClientCredentials = true;

        HttpResponse response;

        // Delete read only user
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/sarek", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch read only users
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers/sarek",
            "[{ \"op\": \"add\", \"path\": \"/sarek/description\", \"value\": \"foo\" }]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Put read only users
        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/sarek",
            "{ \"opendistro_security_roles\": [\"opendistro_security_reserved\"]}",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch single read only user
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers/sarek",
            "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch multiple read only users
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/sarek/description\", \"value\": \"foo\" }]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Get hidden role
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/hide", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Delete hidden user
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/hide", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Patch hidden users
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers/hide",
            "[{ \"op\": \"add\", \"path\": \"/sarek/description\", \"value\": \"foo\" }]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Put hidden users
        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/hide",
            "{ \"opendistro_security_roles\": [\"opendistro_security_reserved\"]}",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Put reserved role is forbidden for non-superadmin
        response = rh.executePutRequest(
            ENDPOINT + "/internalusers/nagilum",
            "{ \"opendistro_security_roles\": [\"opendistro_security_reserved\"]}",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("message"), "Resource 'opendistro_security_reserved' is reserved.");

        // Patch single hidden user
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers/hide",
            "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Patch multiple hidden users
        response = rh.executePatchRequest(
            ENDPOINT + "/internalusers",
            "[{ \"op\": \"add\", \"path\": \"/hide/description\", \"value\": \"foo\" }]",
            new Header[0]
        );
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
    }

    @Test
    public void restrictedUsernameContents() throws Exception {
        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        RESTRICTED_FROM_USERNAME.stream().forEach(restrictedTerm -> {
            final String username = "nag" + restrictedTerm + "ilum";
            final String url = ENDPOINT + "/internalusers/" + username;
            final String bodyWithDefaultPasswordHash = "{\"hash\": \"456\"}";
            final HttpResponse response = rh.executePutRequest(url, bodyWithDefaultPasswordHash);

            assertThat("Expected " + username + " to be rejected", response.getStatusCode(), equalTo(HttpStatus.SC_BAD_REQUEST));
            assertThat(response.getBody(), containsString(restrictedTerm));
        });
    }

    @Test
    public void checkNullElementsInArray() throws Exception {
        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        String body = FileHelper.loadFile("restapi/users_null_array_element.json");
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/internalusers/picard", body);
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT.message(), settings.get("reason"));
    }

    @Test
    public void testGeneratedPasswordContents() {
        String password = UserService.generatePassword();
        PasswordData data = new PasswordData(password);

        LengthRule lengthRule = new LengthRule(8, 16);

        CharacterCharacteristicsRule characteristicsRule = new CharacterCharacteristicsRule();

        // Define M (3 in this case)
        characteristicsRule.setNumberOfCharacteristics(3);

        // Define elements of N (upper, lower, digit, symbol)
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.Digit, 1));
        characteristicsRule.getRules().add(new CharacterRule(EnglishCharacterData.Special, 1));

        org.passay.PasswordValidator validator = new org.passay.PasswordValidator(lengthRule, characteristicsRule);
        validator.validate(data);

        String password2 = UserService.generatePassword();
        PasswordData data2 = new PasswordData(password2);
        assertNotEquals(password, password2);
        assertNotEquals(data, data2);
    }
}
