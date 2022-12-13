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
import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.dlic.rest.api.InternalUsersApiAction.RESTRICTED_FROM_USERNAME;


public class UserApiTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT; 
    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public UserApiTest(){
        ENDPOINT = getEndpointPrefix() + "/api";
    }

    @Test
    public void testSecurityRoles() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration, 6 users
        HttpResponse response = rh
                .executeGetRequest(ENDPOINT + "/" + CType.INTERNALUSERS.toLCString());
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(56, settings.size());
        response = rh.executePatchRequest(ENDPOINT + "/internalusers", "[{ \"op\": \"add\", \"path\": \"/newuser\", \"value\": {\"password\": \"newuser\", \"opendistro_security_roles\": [\"opendistro_security_all_access\"] } }]", new Header[0]);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(ENDPOINT + "/internalusers/newuser", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"opendistro_security_roles\":[\"opendistro_security_all_access\"]"));

        checkGeneralAccess(HttpStatus.SC_OK, "newuser", "newuser");
    }

    @Test
    public void testParallelPutRequests() throws Exception {
        
        setup();
        
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        HttpResponse[] responses = rh.executeMultipleAsyncPutRequest(10, ENDPOINT + "/internalusers/test1", "{\"password\":\"test1\"}");
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

    @Test
    public void testUserApi() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration, 6 users
        HttpResponse response = rh
                .executeGetRequest(ENDPOINT + "/" + CType.INTERNALUSERS.toLCString());
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(56, settings.size());
        // --- GET

        // GET, user admin, exists
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", new Header[0]);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(7, settings.size());
        // hash must be filtered
        Assert.assertEquals("", settings.get("admin.hash"));

        // GET, user does not exist
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/nothinghthere", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // GET, new URL endpoint in security
        response = rh.executeGetRequest(ENDPOINT + "/user/", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // GET, new URL endpoint in security
        response = rh.executeGetRequest(ENDPOINT + "/user", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // -- PUT

        // no username given
        response = rh.executePutRequest(ENDPOINT + "/internalusers/", "{\"hash\": \"123\"}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        // Faulty JSON payload
        response = rh.executePutRequest(ENDPOINT + "/internalusers/nagilum", "{some: \"thing\" asd  other: \"thing\"}",
                new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("reason"), AbstractConfigurationValidator.ErrorType.BODY_NOT_PARSEABLE.getMessage());

        // Missing quotes in JSON - parseable in 6.x, but wrong config keys
        response = rh.executePutRequest(ENDPOINT + "/internalusers/nagilum", "{some: \"thing\", other: \"thing\"}",
                new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        //JK: this should be "Could not parse content of request." because JSON is truly invalid
        //Assert.assertEquals(settings.get("reason"), AbstractConfigurationValidator.ErrorType.INVALID_CONFIGURATION.getMessage());
        //Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("some"));
        //Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("other"));

        // Get hidden role
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/hide" , new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"hidden\":true"));

        // Associating with hidden role is allowed (for superadmin)
        response = rh.executePutRequest(ENDPOINT + "/internalusers/test", "{ \"opendistro_security_roles\": " +
                "[\"opendistro_security_hidden\"]}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // Associating with reserved role is allowed (for superadmin)
        response = rh.executePutRequest(ENDPOINT + "/internalusers/test", "{ \"opendistro_security_roles\": [\"opendistro_security_reserved\"], " +
                "\"hash\": \"123\"}",
            new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // Associating with non-existent role is not allowed
        response = rh.executePutRequest(ENDPOINT + "/internalusers/nagilum", "{ \"opendistro_security_roles\": [\"non_existent\"]}",
            new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("message"), "Role 'non_existent' is not available for role-mapping.");

        // Wrong config keys
        response = rh.executePutRequest(ENDPOINT + "/internalusers/nagilum", "{\"some\": \"thing\", \"other\": \"thing\"}",
                new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("reason"), AbstractConfigurationValidator.ErrorType.INVALID_CONFIGURATION.getMessage());
        Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("some"));
        Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("other"));

        // -- PATCH
        // PATCH on non-existing resource
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers/imnothere", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH read only resource, must be forbidden,
        // but SuperAdmin can PATCH read-only resource
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers/sarek", "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH hidden resource, must be not found, can be found for super admin
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers/q", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers/test", "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH password
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers/test", "[{ \"op\": \"add\", \"path\": \"/password\", \"value\": \"neu\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/test", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertFalse(settings.hasValue("test.password"));
        Assert.assertTrue(settings.hasValue("test.hash"));

        // -- PATCH on whole config resource
        // PATCH on non-existing resource
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers", "[{ \"op\": \"add\", \"path\": \"/imnothere/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH read only resource, must be forbidden,
        // but SuperAdmin can PATCH read only resouce
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers", "[{ \"op\": \"add\", \"path\": \"/sarek/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        rh.sendAdminCertificate = false;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers", "[{ \"op\": \"add\", \"path\": \"/sarek/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // PATCH hidden resource, must be bad request
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers", "[{ \"op\": \"add\", \"path\": \"/q/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers", "[{ \"op\": \"add\", \"path\": \"/test/hidden\", \"value\": true }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH
        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest(ENDPOINT + "/internalusers", "[{ \"op\": \"add\", \"path\": \"/bulknew1\", \"value\": {\"password\": \"bla\", \"backend_roles\": [\"vulcan\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/bulknew1", new Header[0]);
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
        rh.sendAdminCertificate = true;
        addUserWithHash("sarek", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_OK);

        // add/update user, user is hidden, forbidden, allowed for super admin
        rh.sendAdminCertificate = true;
        addUserWithHash("q", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_OK);

        // add users
        rh.sendAdminCertificate = true;
        addUserWithHash("nagilum", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_CREATED);

        // access must be allowed now
        checkGeneralAccess(HttpStatus.SC_OK, "nagilum", "nagilum");

        // try remove user, no username
        rh.sendAdminCertificate = true;
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        // try remove user, nonexisting user
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/picard", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // try remove readonly user
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/sarek", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // try remove hidden user, allowed for super admin
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/q", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("'q' deleted."));
        // now really remove user
        deleteUser("nagilum");

        // Access must be forbidden now
        rh.sendAdminCertificate = false;
        checkGeneralAccess(HttpStatus.SC_UNAUTHORIZED, "nagilum", "nagilum");

        // use password instead of hash
        rh.sendAdminCertificate = true;
        addUserWithPassword("nagilum", "correctpassword", HttpStatus.SC_CREATED);

        rh.sendAdminCertificate = false;
        checkGeneralAccess(HttpStatus.SC_UNAUTHORIZED, "nagilum", "wrongpassword");
        checkGeneralAccess(HttpStatus.SC_OK, "nagilum", "correctpassword");

        deleteUser("nagilum");

        // Check unchanged password functionality
        rh.sendAdminCertificate = true;

        // new user, password or hash is mandatory
        addUserWithoutPasswordOrHash("nagilum", new String[]{"starfleet"}, HttpStatus.SC_BAD_REQUEST);
        // new user, add hash
        addUserWithHash("nagilum", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_CREATED);
        // update user, do not specify hash or password, hash must remain the same
        addUserWithoutPasswordOrHash("nagilum", new String[]{"starfleet"}, HttpStatus.SC_OK);
        // get user, check hash, must be untouched
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/nagilum", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertTrue(settings.get("nagilum.hash").equals(""));


        // ROLES
        // create index first
        setupStarfleetIndex();

        // wrong datatypes in roles file
        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(ENDPOINT + "/internalusers/picard", FileHelper.loadFile("restapi/users_wrong_datatypes.json"), new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
        Assert.assertTrue(settings.get("backend_roles").equals("Array expected"));
        rh.sendAdminCertificate = false;

        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(ENDPOINT + "/internalusers/picard", FileHelper.loadFile("restapi/users_wrong_datatypes.json"), new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
        Assert.assertTrue(settings.get("backend_roles").equals("Array expected"));
        rh.sendAdminCertificate = false;

        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(ENDPOINT + "/internalusers/picard", FileHelper.loadFile("restapi/users_wrong_datatypes2.json"), new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
        Assert.assertTrue(settings.get("password").equals("String expected"));
        Assert.assertTrue(settings.get("backend_roles") == null);
        rh.sendAdminCertificate = false;

        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(ENDPOINT + "/internalusers/picard", FileHelper.loadFile("restapi/users_wrong_datatypes3.json"), new Header[0]);
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
        Assert.assertTrue(settings.get("backend_roles").equals("Array expected"));
        rh.sendAdminCertificate = false;

        // use backendroles when creating user. User picard does not exist in
        // the internal user DB
        // and is also not assigned to any role by username
        addUserWithPassword("picard", "picard", HttpStatus.SC_CREATED);
        // changed in ES5, you now need cluster:monitor/main which pucard does not have
        checkGeneralAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard");

        // check read access to starfleet index and _doc type, must fail
        checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "_doc", 0);

        // overwrite user picard, and give him role "starfleet".
        addUserWithPassword("picard", "picard", new String[]{"starfleet"}, HttpStatus.SC_OK);

        checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "_doc", 1);

        // overwrite user picard, and give him role "starfleet" plus "captains. Now
        // document can be created.
        addUserWithPassword("picard", "picard", new String[]{"starfleet", "captains"}, HttpStatus.SC_OK);
        checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "_doc", 0);
        checkWriteAccess(HttpStatus.SC_CREATED, "picard", "picard", "sf", "_doc", 1);

        rh.sendAdminCertificate = true;
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/picard", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals("", settings.get("picard.hash"));
        roles = settings.getAsList("picard.backend_roles");
        Assert.assertNotNull(roles);
        Assert.assertEquals(2, roles.size());
        Assert.assertTrue(roles.contains("starfleet"));
        Assert.assertTrue(roles.contains("captains"));

        addUserWithPassword("$1aAAAAAAAAC", "$1aAAAAAAAAC", HttpStatus.SC_CREATED);
        addUserWithPassword("abc", "abc", HttpStatus.SC_CREATED);


        // check tabs in json
        response = rh.executePutRequest(ENDPOINT + "/internalusers/userwithtabs", "\t{\"hash\": \t \"123\"\t}  ", new Header[0]);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());
    }

    @Test
    public void testPasswordRules() throws Exception {

        Settings nodeSettings =
                Settings.builder()
                        .put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, "xxx")
                        .put(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX,
                                "(?=.*[A-Z])(?=.*[^a-zA-Z\\\\d])(?=.*[0-9])(?=.*[a-z]).{8,}")
                        .build();

        setup(nodeSettings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration, 6 users
        HttpResponse response = rh
                .executeGetRequest("_plugins/_security/api/" + CType.INTERNALUSERS.toLCString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(response.getBody());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(56, settings.size());

        addUserWithPassword("tooshoort", "", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword("tooshoort", "123", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword("tooshoort", "1234567", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword("tooshoort", "1Aa%", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword("no-nonnumeric", "123456789", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword("no-uppercase", "a123456789", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword("no-lowercase", "A123456789", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword("ok1", "a%A123456789", HttpStatus.SC_CREATED);
        addUserWithPassword("ok2", "$aA123456789", HttpStatus.SC_CREATED);
        addUserWithPassword("ok3", "$Aa123456789", HttpStatus.SC_CREATED);
        addUserWithPassword("ok4", "$1aAAAAAAAAA", HttpStatus.SC_CREATED);
        addUserWithPassword("empty_password_no_hash", "", HttpStatus.SC_BAD_REQUEST);
        addUserWithPasswordAndHash("empty_password", "", "$%^123", HttpStatus.SC_BAD_REQUEST);
        addUserWithPasswordAndHash("null_password", null, "$%^123", HttpStatus.SC_BAD_REQUEST);

        response = rh.executePatchRequest(PLUGINS_PREFIX + "/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/ok4\", \"value\": {\"password\": \"bla\", \"backend_roles\": [\"vulcan\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePatchRequest(PLUGINS_PREFIX + "/api/internalusers", "[{ \"op\": \"replace\", \"path\": \"/ok4\", \"value\": {\"password\": \"bla\", \"backend_roles\": [\"vulcan\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        addUserWithPassword("ok4", "123", HttpStatus.SC_BAD_REQUEST);

        response = rh.executePatchRequest(PLUGINS_PREFIX + "/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/ok4\", \"value\": {\"password\": \"$1aAAAAAAAAB\", \"backend_roles\": [\"vulcan\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        addUserWithPassword("ok4", "$1aAAAAAAAAC", HttpStatus.SC_OK);

        //its not allowed to use the username as password (case insensitive)
        response = rh.executePatchRequest(PLUGINS_PREFIX + "/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/$1aAAAAAAAAB\", \"value\": {\"password\": \"$1aAAAAAAAAB\", \"backend_roles\": [\"vulcan\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        addUserWithPassword("$1aAAAAAAAAC", "$1aAAAAAAAAC", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword("$1aAAAAAAAac", "$1aAAAAAAAAC", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword(URLEncoder.encode("$1aAAAAAAAac%", "UTF-8"), "$1aAAAAAAAAC%", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword(URLEncoder.encode("$1aAAAAAAAac%!=\"/\\;:test&~@^", "UTF-8").replace("+", "%2B"), "$1aAAAAAAAac%!=\\\"/\\\\;:test&~@^", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword(URLEncoder.encode("$1aAAAAAAAac%!=\"/\\;: test&", "UTF-8"), "$1aAAAAAAAac%!=\\\"/\\\\;: test&123", HttpStatus.SC_BAD_REQUEST);

        response = rh.executeGetRequest(PLUGINS_PREFIX + "/api/internalusers/nothinghthere?pretty", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("NOT_FOUND"));

        String patchPayload = "[ " +
                "{ \"op\": \"add\", \"path\": \"/testuser1\",  \"value\": { \"password\": \"$aA123456789\", \"backend_roles\": [\"testrole1\"] } }," +
                "{ \"op\": \"add\", \"path\": \"/testuser2\",  \"value\": { \"password\": \"testpassword2\", \"backend_roles\": [\"testrole2\"] } }" +
                "]";

        response = rh.executePatchRequest(PLUGINS_PREFIX + "/api/internalusers", patchPayload, new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("error"));
        Assert.assertTrue(response.getBody().contains("xxx"));

        response = rh.executePutRequest(PLUGINS_PREFIX + "/api/internalusers/ok1", "{\"backend_roles\":[\"my-backend-role\"],\"attributes\":{},\"password\":\"\"}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest(PLUGINS_PREFIX + "/api/internalusers/ok1", "{\"backend_roles\":[\"my-backend-role\"],\"attributes\":{},\"password\":\"Admin_123\"}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(PLUGINS_PREFIX + "/api/internalusers/ok1", "{\"backend_roles\":[\"my-backend-role\"],\"attributes\":{}}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(PLUGINS_PREFIX + "/api/internalusers/ok1", "{\"backend_roles\":[\"my-backend-role\"],\"attributes\":{},\"password\":\"bla\"}",
                new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void testUserApiWithDots() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration, 6 users
        HttpResponse response = rh
                .executeGetRequest(ENDPOINT + "/" + CType.INTERNALUSERS.toLCString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(56, settings.size());

        addUserWithPassword(".my.dotuser0", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_CREATED);

        addUserWithPassword(".my.dot.user0", "12345678",
                HttpStatus.SC_CREATED);

        addUserWithHash(".my.dotuser1", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_CREATED);

        addUserWithPassword(".my.dot.user2", "12345678",
                HttpStatus.SC_CREATED);

    }

    @Test
    public void testUserApiNoPasswordChange() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // initial configuration, 5 users
        HttpResponse response;

        addUserWithHash("user1", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_CREATED);

        response = rh.executePutRequest(ENDPOINT + "/internalusers/user1", "{\"hash\":\"$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m\",\"password\":\"\",\"backend_roles\":[\"admin\",\"rolea\"]}");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/internalusers/user1", "{\"hash\":\"$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m\",\"password\":\"Admin_123\",\"backend_roles\":[\"admin\",\"rolea\"]}");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest(ENDPOINT + "/internalusers/user1");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        addUserWithHash("user2", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_CREATED);

        response = rh.executePutRequest(ENDPOINT + "/internalusers/user2", "{\"password\":\"\",\"backend_roles\":[\"admin\",\"rolex\"]}");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/internalusers/user2", "{\"password\":\"Admin_123\",\"backend_roles\":[\"admin\",\"rolex\"]}");
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
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/sarek" , new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch read only users
        response = rh.executePatchRequest(ENDPOINT + "/internalusers/sarek", "[{ \"op\": \"add\", \"path\": \"/sarek/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Put read only users
        response = rh.executePutRequest(ENDPOINT + "/internalusers/sarek", "{ \"opendistro_security_roles\": [\"opendistro_security_reserved\"]}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch single read only user
        response = rh.executePatchRequest(ENDPOINT + "/internalusers/sarek", "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Patch multiple read only users
        response = rh.executePatchRequest(ENDPOINT + "/internalusers", "[{ \"op\": \"add\", \"path\": \"/sarek/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // Get hidden role
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/hide" , new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Delete hidden user
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/hide" , new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Patch hidden users
        response = rh.executePatchRequest(ENDPOINT + "/internalusers/hide", "[{ \"op\": \"add\", \"path\": \"/sarek/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Put hidden users
        response = rh.executePutRequest(ENDPOINT + "/internalusers/hide", "{ \"opendistro_security_roles\": [\"opendistro_security_reserved\"]}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Put reserved role is forbidden for non-superadmin
        response = rh.executePutRequest(ENDPOINT + "/internalusers/nagilum", "{ \"opendistro_security_roles\": [\"opendistro_security_reserved\"]}",
            new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(settings.get("message"), "Resource 'opendistro_security_reserved' is read-only.");

        // Patch single hidden user
        response = rh.executePatchRequest(ENDPOINT + "/internalusers/hide", "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // Patch multiple hidden users
        response = rh.executePatchRequest(ENDPOINT + "/internalusers", "[{ \"op\": \"add\", \"path\": \"/hide/description\", \"value\": \"foo\" }]", new Header[0]);
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
    public void checkNullElementsInArray() throws Exception{
        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        String body = FileHelper.loadFile("restapi/users_null_array_element.json");
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/internalusers/picard", body, new Header[0]);
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.NULL_ARRAY_ELEMENT.getMessage(), settings.get("reason"));
    }

}
