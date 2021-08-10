/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.opensearch.security.securityconf.impl.CType;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import java.util.Arrays;

import com.amazon.dlic.auth.http.saml.HTTPSamlAuthenticator;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class SavedTenantApiTest extends AbstractRestApiUnitTest {
    private final String BASE_ENDPOINT;
    private final String ENDPOINT;

    public SavedTenantApiTest(String baseEndpoint, String endpoint){
        BASE_ENDPOINT = baseEndpoint;
        ENDPOINT = endpoint;
    }

    @Parameterized.Parameters
    public static Iterable<String[]> endpoints() {
        return Arrays.asList(new String[][] {
                {"/_opendistro/_security/api/", "/_opendistro/_security/api/account"},
                {"/_plugins/_security/api/", "/_plugins/_security/api/account"}
        });
    }

    @Test
    // tests InternalUserV7.getSaved_tenant()
    public void testGetTenant() throws Exception{
        // arrange
        setup();
        final String testUser = "test-user";
        final String testPass = "test-pass";
        final String defaultTenantValue = "global-tenant";
        final String endpoint = BASE_ENDPOINT + "account";

        // add user
        addUserWithPassword(testUser, testPass, HttpStatus.SC_CREATED);

        // test - unauthorized access as credentials are missing.
        HttpResponse response = rh.executeGetRequest(endpoint);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - incorrect password
        response = rh.executeGetRequest(endpoint, encodeBasicHeader(testUser, testPass + "invalidating text"));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - incorrect user; not possible to check until later (when adding a (target) user parameter in body)
        //     can't do this until user manager; check if only users who can manage this user can get/set this info

        // don't need to test if currently saved tenant is unaccessible by user; that's handled when user attempts to
        //     load it

        // test - valid request
        response = rh.executeGetRequest(endpoint, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(defaultTenantValue, body.get("saved_tenant"));
    }

    @Test
    // tests InternalUserV7.setSaved_tenant()
    public void testSetTenant() throws Exception{
        // ======================================= START SETUP ====================================================
        // arrange
        setup();
        final String testUser = "test-user";
        final String testPass = "test-pass";
        final String defaultTenantValue = "global-tenant";
        final String magaariPayload = "{\"saved_tenant\":\"Magaari\"}";
        final String xaanPayload = "{\"saved_tenant\":\"Xaan\"}";
        final String vermillionForestPayload = "{\"saved_tenant\":\"Vermillion_Forest\"}";
        final String nonexistentTenantPayload = "{\"saved_tenant\":\"great_tree_of_eyos\"}";
        final String endpoint = BASE_ENDPOINT + "account";

        // add user
        addUserWithPassword(testUser, testPass, HttpStatus.SC_CREATED);

        // check newly created user has valid saved_tenant value
        HttpResponse response = rh.executeGetRequest(endpoint, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(defaultTenantValue, body.get("saved_tenant"));

        // create new tenants
        rh.sendAdminCertificate = true;
        final String createTenantEndpoint = BASE_ENDPOINT + "tenants/";
        final String newTenantPayload = "{\"description\":\"duelyst dance\"}";
        response = rh.executePutRequest(createTenantEndpoint + "Magaari", newTenantPayload);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        response = rh.executePutRequest(createTenantEndpoint + "Xaan", newTenantPayload);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        response = rh.executePutRequest(createTenantEndpoint + "Vermillion_Forest", newTenantPayload);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = false;

        // create new roles
        rh.sendAdminCertificate = true;
        final String createRoleEndpoint = BASE_ENDPOINT + "roles/";
        final String newRolePayload1 = 
        "{\n" + 
        "   \"tenant_permissions\": [{\n" +
        "       \"tenant_patterns\": [\n" +
        "           \"Magaari\"\n" +
        "       ],\n" +
        "       \"allowed_actions\": [\n" +
        "           \"kibana_all_read\"\n" +
        "       ]\n" +
        "   }]\n" +
        "}";
        final String newRolePayload2 = 
        "{\n" + 
        "   \"tenant_permissions\": [{\n" +
        "       \"tenant_patterns\": [\n" +
        "           \"Xaan\"\n" +
        "       ],\n" +
        "       \"allowed_actions\": [\n" +
        "           \"kibana_all_write\"\n" +
        "       ]\n" +
        "   }]\n" +
        "}";
        response = rh.executePutRequest(createRoleEndpoint + "Magmar", newRolePayload1, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        response = rh.executePutRequest(createRoleEndpoint + "Songhai", newRolePayload2, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = false;

        // assign roles to user
        rh.sendAdminCertificate = true;
        final String createRolesMappingEndpoint = "_plugins/_security/api/rolesmapping/";
        final String roleMappingPayload = 
        "{\n" +
        "   \"backend_roles\": [],\n" +
        "   \"hosts\": [],\n" +
        "   \"users\": [\"" + testUser + "\"]\n" +
        "}";
        response = rh.executePutRequest(createRolesMappingEndpoint + "Magmar", roleMappingPayload, new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        response = rh.executePutRequest(createRolesMappingEndpoint + "Songhai", roleMappingPayload, new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendAdminCertificate = false;

        // ======================================= START PUT TESTS ====================================================
        // test - unauthorized access as credentials are missing.
        response = rh.executePutRequest(endpoint, magaariPayload);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - incorrect password
        response = rh.executePutRequest(endpoint, magaariPayload, encodeBasicHeader(testUser, testPass + "invalidating text"));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - invalid payload
        final String badPayload = "{\"foo\":\"bar\"}";
        response = rh.executePutRequest(endpoint, badPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - specified tenant does not exist
        response = rh.executePutRequest(endpoint, nonexistentTenantPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - user does not have access to tenant
        response = rh.executePutRequest(endpoint, vermillionForestPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // TODO: test - calling user does not have access to manage target user
        //    for future implementation

        // test - valid PUT request for read access
        response = rh.executePutRequest(endpoint, magaariPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // test - valid PUT request for write access
        response = rh.executePutRequest(endpoint, xaanPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }
}
