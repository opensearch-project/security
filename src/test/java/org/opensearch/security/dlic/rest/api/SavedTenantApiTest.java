/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
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
    public void testDefaultTenantValueCheck() throws Exception {
        // arrange
        setup();
        final String testUser = "test-user";
        final String testPass = "test-pass";
        final String defaultTenantValue = "global-tenant";
        final String savedTenantEndpoint = BASE_ENDPOINT + "account/saved_tenant";

        // add user
        addUserWithPassword(testUser, testPass, HttpStatus.SC_CREATED);

        // test - unauthorized access as credentials are missing.
        HttpResponse response = rh.executeGetRequest(savedTenantEndpoint);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - incorrect password
        response = rh.executeGetRequest(savedTenantEndpoint, encodeBasicHeader(testUser, testPass + "invalidating text"));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - incorrect user; not possible to check until later (when adding a (target) user parameter in body)
        // can't do this until user manager; check if only users who can manage this user can get/set this info

        // test - valid request
        response = rh.executeGetRequest(savedTenantEndpoint, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(defaultTenantValue, body.get("saved_tenant"));
    }

    @Test
    public void testSet_tenant() throws Exception{
        // arrange
        setup();
        final String testUser = "test-user";
        final String testPass = "test-pass";
        final String defaultTenantValue = "global-tenant";
        final String newSavedTenant = "shinjuku";
        final String changeSavedTenantPayload = "{\"saved_tenant\":\"" + newSavedTenant + "\"}";
        final String savedTenantEndpoint = BASE_ENDPOINT + "account/saved_tenant";

        // add user
        addUserWithPassword(testUser, testPass, HttpStatus.SC_CREATED);

        // check newly created user has valid saved_tenant value
        HttpResponse response = rh.executeGetRequest(savedTenantEndpoint, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(defaultTenantValue, body.get("saved_tenant"));
        
        // test - unauthorized access as credentials are missing.
        response = rh.executePutRequest(savedTenantEndpoint, changeSavedTenantPayload);
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - incorrect password
        response = rh.executePutRequest(savedTenantEndpoint, changeSavedTenantPayload, encodeBasicHeader(testUser, testPass + "invalidating text"));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        // test - incorrect user; not possible to check until later (when adding a (target) user parameter in body)
        // can't do this until user manager; check if only users who can manage this user can get/set this info

        // test - specified tenant does not exist
        // Set<String> tenants = securityRole.getValue().getTenants().keySet();


        // test - user does not have access to specified tenant

        // test - invalid payload
        final String badPayload = "{\"foo\":\"bar\"}";
        response = rh.executePutRequest(savedTenantEndpoint, badPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // test - valid PUT request
        response = rh.executePutRequest(savedTenantEndpoint, changeSavedTenantPayload, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // check value after calling PUT
        response = rh.executeGetRequest(savedTenantEndpoint, encodeBasicHeader(testUser, testPass));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        body = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertEquals(newSavedTenant, body.get("saved_tenant"));
    }
}
