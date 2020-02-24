/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import java.util.List;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator.ErrorType;
import com.amazon.opendistroforelasticsearch.security.support.SecurityJsonNode;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class RolesApiTest extends AbstractRestApiUnitTest {


    @Test
    public void testPutRole() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;
        // check roles exists
        HttpResponse response = rh.executePutRequest("/_opendistro/_security/api/roles/admin", FileHelper.loadFile("restapi/simple_role.json"));
        System.out.println(response.getBody());
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        response = rh.executePutRequest("/_opendistro/_security/api/roles/lala", "{ \"cluster_permissions\": [\"*\"] }");
        System.out.println(response.getBody());
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        response = rh.executePutRequest("/_opendistro/_security/api/roles/empty", "{ \"cluster_permissions\": [] }");
        System.out.println(response.getBody());
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
    }

    @Test
    public void testAllRolesNotContainMetaHeader() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;
        HttpResponse response = rh.executeGetRequest("_opendistro/_security/api/roles");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("_meta"));
    }

    @Test
    public void testPutDuplicateKeys() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;
        HttpResponse response = rh.executePutRequest("_opendistro/_security/api/roles/dup", "{ \"cluster_permissions\": [\"*\"], \"cluster_permissions\": [\"*\"] }");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("JsonParseException"));
        assertHealthy();
    }

    @Test
    public void testPutUnknownKey() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;
        HttpResponse response = rh.executePutRequest("_opendistro/_security/api/roles/dup", "{ \"unknownkey\": [\"*\"], \"cluster_permissions\": [\"*\"] }");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("invalid_keys"));
        assertHealthy();
    }

    @Test
    public void testPutInvalidJson() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;
        HttpResponse response = rh.executePutRequest("_opendistro/_security/api/roles/dup", "{ \"invalid\"::{{ [\"*\"], \"cluster_permissions\": [\"*\"] }");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("JsonParseException"));
        assertHealthy();
    }

    @Test
    public void testRolesApi() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;

        // check roles exists
        HttpResponse response = rh.executeGetRequest("/_opendistro/_security/api/roles");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // -- GET

        // GET opendistro_security_role_starfleet
        response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        JsonNode settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(1, settings.size());

        // GET, role does not exist
        response = rh.executeGetRequest("/_opendistro/_security/api/roles/nothinghthere", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        response = rh.executeGetRequest("/_opendistro/_security/api/roles/", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("/_opendistro/_security/api/roles", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("\"cluster_permissions\":[\"*\"]"));
        Assert.assertFalse(response.getBody().contains("\"cluster_permissions\" : ["));

        response = rh.executeGetRequest("/_opendistro/_security/api/roles?pretty", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertFalse(response.getBody().contains("\"cluster_permissions\":[\"*\"]"));
        Assert.assertTrue(response.getBody().contains("\"cluster_permissions\" : ["));

        // hidden role
        response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_internal", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // create index
        setupStarfleetIndex();

        // add user picard, role starfleet, maps to opendistro_security_role_starfleet
        addUserWithPassword("picard", "picard", new String[] { "starfleet", "captains" }, HttpStatus.SC_CREATED);
        checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);

        // ES7 only supports one doc type, so trying to create a second one leads to 400  BAD REQUEST
        checkWriteAccess(HttpStatus.SC_BAD_REQUEST, "picard", "picard", "sf", "public", 0);


        // -- DELETE

        rh.sendHTTPClientCertificate = true;

        // Non-existing role
        response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/idonotexist", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // read only role, SuperAdmin can delete the read-only role
        response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/opendistro_security_transport_client", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // hidden role
        response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/opendistro_security_internal", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // remove complete role mapping for opendistro_security_role_starfleet_captains
        response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        rh.sendHTTPClientCertificate = false;

        // user has only role starfleet left, role has READ access only
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 1);

        // ES7 only supports one doc type, but Opendistro permission checks run first
        // So we also get a 403 FORBIDDEN when tring to add new document type
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "public", 0);

        rh.sendHTTPClientCertificate = true;
        // remove also starfleet role, nothing is allowed anymore
        response = rh.executeDeleteRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
        checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);

        // -- PUT
        // put with empty roles, must fail
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", "", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.PAYLOAD_MANDATORY.getMessage(), settings.get("reason").asText());

        // put new configuration with invalid payload, must fail
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet",
                FileHelper.loadFile("restapi/roles_not_parseable.json"), new Header[0]);
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.BODY_NOT_PARSEABLE.getMessage(), settings.get("reason").asText());

        // put new configuration with invalid keys, must fail
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet",
                FileHelper.loadFile("restapi/roles_invalid_keys.json"), new Header[0]);
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.INVALID_CONFIGURATION.getMessage(), settings.get("reason").asText());
        Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY).get("keys").asText().contains("indexx_permissions"));
        Assert.assertTrue(
                settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY).get("keys").asText().contains("kluster_permissions"));

        // put new configuration with wrong datatypes, must fail
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet",
                FileHelper.loadFile("restapi/roles_wrong_datatype.json"), new Header[0]);
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason").asText());
        Assert.assertTrue(settings.get("cluster_permissions").asText().equals("Array expected"));

        // put read only role, must be forbidden
        // But SuperAdmin can still create it
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_transport_client",
                FileHelper.loadFile("restapi/roles_captains.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

        // put hidden role, must be forbidden
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_internal",
                FileHelper.loadFile("restapi/roles_captains.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // restore starfleet role
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet",
                FileHelper.loadFile("restapi/roles_starfleet.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendHTTPClientCertificate = false;
        checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);

        // now picard is only in opendistro_security_role_starfleet, which has write access to
        // all indices. We collapse all document types in ODFE7 so this permission in the
        // starfleet role grants all permissions:
        //   public:  
        //       - 'indices:*'		
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
        // ES7 only supports one doc type, so trying to create a second one leads to 400  BAD REQUEST
        checkWriteAccess(HttpStatus.SC_BAD_REQUEST, "picard", "picard", "sf", "public", 0);

        rh.sendHTTPClientCertificate = true;

        // restore captains role
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/roles_captains.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());
        rh.sendHTTPClientCertificate = false;
        checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
        checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);

        // ES7 only supports one doc type, so trying to create a second one leads to 400  BAD REQUEST
        checkWriteAccess(HttpStatus.SC_BAD_REQUEST, "picard", "picard", "sf", "public", 0);

        rh.sendHTTPClientCertificate = true;
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/roles_complete_invalid.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

//		rh.sendHTTPClientCertificate = true;
//		response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
//				FileHelper.loadFile("restapi/roles_multiple.json"), new Header[0]);
//		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/roles_multiple_2.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // check tenants
        rh.sendHTTPClientCertificate = true;
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/roles_captains_tenants.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(2, settings.size());
        Assert.assertEquals(settings.get("status").asText(), "OK");


        response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(response.getBody());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(1, settings.size());
        Assert.assertEquals(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(1).get("tenant_patterns").get(0).asString(), "tenant1");
        Assert.assertEquals(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(1).get("allowed_actions").get(0).asString(), "kibana_all_read");

        Assert.assertEquals(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(0).get("tenant_patterns").get(0).asString(), "tenant2");
        Assert.assertEquals(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(0).get("allowed_actions").get(0).asString(), "kibana_all_write");


        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/roles_captains_tenants2.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(2, settings.size());
        Assert.assertEquals(settings.get("status").asText(), "OK");

        response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(1, settings.size());

        Assert.assertEquals(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(0).get("tenant_patterns").get(0).asString(), "tenant2");
        Assert.assertEquals(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(0).get("tenant_patterns").get(1).asString(), "tenant4");

        Assert.assertEquals(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(0).get("allowed_actions").get(0).asString(), "kibana_all_write");

        Assert.assertEquals(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(1).get("tenant_patterns").get(0).asString(), "tenant1");
        Assert.assertEquals(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(1).get("tenant_patterns").get(1).asString(), "tenant3");
        Assert.assertEquals(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(1).get("allowed_actions").get(0).asString(), "kibana_all_read");

        // remove tenants from role
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/roles_captains_no_tenants.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(2, settings.size());
        Assert.assertEquals(settings.get("status").asText(), "OK");

        response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(1, settings.size());
        Assert.assertFalse(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.cluster_permissions").get(0).isNull());
        Assert.assertTrue(new SecurityJsonNode(settings).getDotted("opendistro_security_role_starfleet_captains.tenant_permissions").get(0).isNull());

        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet_captains",
                FileHelper.loadFile("restapi/roles_captains_tenants_malformed.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        Assert.assertEquals(settings.get("status").asText(), "error");
        Assert.assertEquals(settings.get("reason").asText(), ErrorType.INVALID_CONFIGURATION.getMessage());

        // -- PATCH
        // PATCH on non-existing resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles/imnothere", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        // SuperAdmin can patch it
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles/opendistro_security_transport_client", "[{ \"op\": \"add\", \"path\": \"/description\", \"value\": \"foo\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH hidden resource, must be not found
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles/opendistro_security_internal", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody(), response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        List<String> permissions = null;

        // PATCH 
        /*
         * how to patch with new v7 config format?
         * rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", "[{ \"op\": \"add\", \"path\": \"/index_permissions/sf/ships/-\", \"value\": \"SEARCH\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_opendistro/_security/api/roles/opendistro_security_role_starfleet", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());       
        permissions = DefaultObjectMapper.objectMapper.convertValue(settings.get("opendistro_security_role_starfleet").get("indices").get("sf").get("ships"), List.class);
        Assert.assertNotNull(permissions);
        Assert.assertEquals(2, permissions.size());
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_READ"));
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_SEARCH")); */

        // -- PATCH on whole config resource
        // PATCH on non-existing resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"add\", \"path\": \"/imnothere/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_transport_client/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH hidden resource, must be bad request
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"add\", \"path\": \"/opendistro_security_internal/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH delete read only resource, must be forbidden
        // SuperAdmin can delete read only user
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"remove\", \"path\": \"/opendistro_security_transport_client\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // PATCH hidden resource, must be bad request
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"remove\", \"path\": \"/opendistro_security_internal\"}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH value of hidden flag, must fail with validation error
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"add\", \"path\": \"/newnewnew\", \"value\": {  \"hidden\": true, \"index_permissions\" : [ {\"index_patterns\" : [ \"sf\" ],\"allowed_actions\" : [ \"OPENDISTRO_SECURITY_READ\" ]}] }}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));

        // PATCH 
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"add\", \"path\": \"/bulknew1\", \"value\": {   \"index_permissions\" : [ {\"index_patterns\" : [ \"sf\" ],\"allowed_actions\" : [ \"OPENDISTRO_SECURITY_READ\" ]}] }}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_opendistro/_security/api/roles/bulknew1", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = DefaultObjectMapper.readTree(response.getBody());
        permissions =  new SecurityJsonNode(settings).get("bulknew1").get("index_permissions").get(0).get("allowed_actions").asList();
        Assert.assertNotNull(permissions);
        Assert.assertEquals(1, permissions.size());
        Assert.assertTrue(permissions.contains("OPENDISTRO_SECURITY_READ"));

        // delete resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/roles", "[{ \"op\": \"remove\", \"path\": \"/bulknew1\"}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_opendistro/_security/api/roles/bulknew1", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // put valid field masks
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_field_mask_valid",
                FileHelper.loadFile("restapi/roles_field_masks_valid.json"), new Header[0]);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());

        // put invalid field masks
        response = rh.executePutRequest("/_opendistro/_security/api/roles/opendistro_security_field_mask_invalid",
                FileHelper.loadFile("restapi/roles_field_masks_invalid.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

    }
}
