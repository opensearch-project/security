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

import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.AuditTestUtils;
import org.opensearch.security.dlic.rest.validation.PasswordValidator;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH;

public abstract class AbstractRestApiUnitTest extends SingleClusterTest {

    protected RestHelper rh = null;
    protected boolean init = true;

    @Override
    protected String getResourceFolder() {
        return "restapi";
    }

    @Override
    protected final void setup() throws Exception {
        Settings.Builder builder = Settings.builder();

        builder.put("plugins.security.ssl.http.enabled", true)
            .put(SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH, PasswordValidator.ScoreStrength.FAIR.name())
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("restapi/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("restapi/truststore.jks"));

        setup(Settings.EMPTY, new DynamicSecurityConfig(), builder.build(), init);
        rh = restHelper();
        rh.keystore = "restapi/kirk-keystore.jks";
    }

    @Override
    protected final void setup(Settings nodeOverride) throws Exception {
        Settings.Builder builder = Settings.builder();

        builder.put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("restapi/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("restapi/truststore.jks"))
            .put(nodeOverride);

        setup(Settings.EMPTY, new DynamicSecurityConfig(), builder.build(), init);
        rh = restHelper();
        rh.keystore = "restapi/kirk-keystore.jks";
    }

    protected final void setupWithRestRoles() throws Exception {
        setupWithRestRoles(null);
    }

    protected final void setupWithRestRoles(Settings nodeOverride) throws Exception {
        Settings.Builder builder = Settings.builder();

        builder.put("plugins.security.ssl.http.enabled", true)
            .put(SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH, PasswordValidator.ScoreStrength.FAIR.name())
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("restapi/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("restapi/truststore.jks"));

        builder.put(rolesSettings());

        if (null != nodeOverride) {
            builder.put(nodeOverride);
        }

        setup(Settings.EMPTY, new DynamicSecurityConfig(), builder.build(), init);
        rh = restHelper();
        rh.keystore = "restapi/kirk-keystore.jks";

        AuditTestUtils.updateAuditConfig(rh, nodeOverride != null ? nodeOverride : Settings.EMPTY);
    }

    protected Settings rolesSettings() {
        return Settings.builder()
            .put("plugins.security.restapi.roles_enabled.0", "opendistro_security_role_klingons")
            .put("plugins.security.restapi.roles_enabled.1", "opendistro_security_role_vulcans")
            .put("plugins.security.restapi.roles_enabled.2", "opendistro_security_test")
            .put("plugins.security.restapi.endpoints_disabled.global.CACHE.0", "*")
            .put("plugins.security.restapi.endpoints_disabled.opendistro_security_role_klingons.conFiGuration.0", "*")
            .put("plugins.security.restapi.endpoints_disabled.opendistro_security_role_klingons.wRongType.0", "WRONGType")
            .put("plugins.security.restapi.endpoints_disabled.opendistro_security_role_klingons.ROLESMAPPING.0", "PUT")
            .put("plugins.security.restapi.endpoints_disabled.opendistro_security_role_klingons.ROLESMAPPING.1", "DELETE")
            .put("plugins.security.restapi.endpoints_disabled.opendistro_security_role_vulcans.CONFIG.0", "*")
            .build();
    }

    protected void deleteUser(String username) throws Exception {
        boolean sendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executeDeleteRequest("/_opendistro/_security/api/internalusers/" + username, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        rh.sendAdminCertificate = sendAdminCertificate;
    }

    protected void addUserWithPassword(String username, String password, int status) throws Exception {
        addUserWithPassword(username, password, status, null);
    }

    protected void addUserWithPassword(String username, String password, int status, String message) throws Exception {
        boolean sendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executePutRequest(
            "/_opendistro/_security/api/internalusers/" + username,
            "{\"password\": \"" + password + "\"}",
            new Header[0]
        );
        Assert.assertEquals(status, response.getStatusCode());
        rh.sendAdminCertificate = sendAdminCertificate;
        if (Objects.nonNull(message)) {
            Assert.assertTrue(response.getBody().contains(message));
        }
    }

    protected void addUserWithPassword(String username, String password, String[] roles, int status) throws Exception {
        boolean sendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = true;
        String payload = "{" + "\"password\": \"" + password + "\"," + "\"backend_roles\": [";
        for (int i = 0; i < roles.length; i++) {
            payload += "\"" + roles[i] + "\"";
            if (i + 1 < roles.length) {
                payload += ",";
            }
        }
        payload += "]}";
        HttpResponse response = rh.executePutRequest("/_opendistro/_security/api/internalusers/" + username, payload, new Header[0]);
        Assert.assertEquals(response.getBody(), status, response.getStatusCode());
        rh.sendAdminCertificate = sendAdminCertificate;
    }

    protected void addUserWithoutPasswordOrHash(String username, String[] roles, int status) throws Exception {
        boolean sendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = true;
        String payload = "{ \"backend_roles\": [";
        for (int i = 0; i < roles.length; i++) {
            payload += "\" " + roles[i] + " \"";
            if (i + 1 < roles.length) {
                payload += ",";
            }
        }
        payload += "]}";
        HttpResponse response = rh.executePutRequest("/_opendistro/_security/api/internalusers/" + username, payload, new Header[0]);
        Assert.assertEquals(status, response.getStatusCode());
        rh.sendAdminCertificate = sendAdminCertificate;
    }

    protected void addUserWithHash(String username, String hash) throws Exception {
        addUserWithHash(username, hash, HttpStatus.SC_OK);
    }

    protected void addUserWithHash(String username, String hash, int status) throws Exception {
        boolean sendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executePutRequest(
            "/_opendistro/_security/api/internalusers/" + username,
            "{\"hash\": \"" + hash + "\"}",
            new Header[0]
        );
        Assert.assertEquals(status, response.getStatusCode());
        rh.sendAdminCertificate = sendAdminCertificate;
    }

    protected void addUserWithPasswordAndHash(String username, String password, String hash, int status) throws Exception {
        boolean sendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = true;
        HttpResponse response = rh.executePutRequest(
            "/_opendistro/_security/api/internalusers/" + username,
            "{\"hash\": \"" + hash + "\", \"password\": \"" + password + "\"}",
            new Header[0]
        );
        Assert.assertEquals(status, response.getStatusCode());
        rh.sendAdminCertificate = sendAdminCertificate;
    }

    protected void checkGeneralAccess(int status, String username, String password) throws Exception {
        boolean sendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = false;
        Assert.assertEquals(status, rh.executeGetRequest("", encodeBasicHeader(username, password)).getStatusCode());
        rh.sendAdminCertificate = sendAdminCertificate;
    }

    protected String checkReadAccess(int status, String username, String password, String indexName, String actionType, int id)
        throws Exception {
        rh.sendAdminCertificate = false;
        String action = indexName + "/" + actionType + "/" + id;
        HttpResponse response = rh.executeGetRequest(action, encodeBasicHeader(username, password));
        int returnedStatus = response.getStatusCode();
        Assert.assertEquals(status, returnedStatus);
        return response.getBody();

    }

    protected String checkWriteAccess(int status, String username, String password, String indexName, String actionType, int id)
        throws Exception {
        rh.sendAdminCertificate = false;
        String action = indexName + "/" + actionType + "/" + id;
        String payload = "{\"value\" : \"true\"}";
        HttpResponse response = rh.executePutRequest(action, payload, encodeBasicHeader(username, password));
        int returnedStatus = response.getStatusCode();
        Assert.assertEquals(status, returnedStatus);
        return response.getBody();
    }

    protected void setupStarfleetIndex() throws Exception {
        boolean sendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = true;
        rh.executePutRequest("sf", null, new Header[0]);
        rh.executePutRequest("sf/_doc/0", "{\"number\" : \"NCC-1701-D\"}", new Header[0]);
        rh.executePutRequest("sf/_doc/0", "{\"some\" : \"value\"}", new Header[0]);
        rh.sendAdminCertificate = sendAdminCertificate;
    }

    protected void assertHealthy() throws Exception {
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_opendistro/_security/health?pretty").getStatusCode());
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("_opendistro/_security/authinfo?pretty", encodeBasicHeader("admin", "admin")).getStatusCode()
        );
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("admin", "admin")).getStatusCode()
        );
    }

    String createRestAdminPermissionsPayload(String... additionPerms) throws JsonProcessingException {
        final ObjectNode rootNode = DefaultObjectMapper.objectMapper.createObjectNode();
        rootNode.set("cluster_permissions", clusterPermissionsForRestAdmin(additionPerms));
        return DefaultObjectMapper.objectMapper.writeValueAsString(rootNode);
    }

    ArrayNode clusterPermissionsForRestAdmin(String... additionPerms) {
        final ArrayNode permissionsArray = DefaultObjectMapper.objectMapper.createArrayNode();
        for (final Map.Entry<
            Endpoint,
            RestApiAdminPrivilegesEvaluator.PermissionBuilder> entry : RestApiAdminPrivilegesEvaluator.ENDPOINTS_WITH_PERMISSIONS
                .entrySet()) {
            if (entry.getKey() == Endpoint.SSL) {
                permissionsArray.add(entry.getValue().build("certs")).add(entry.getValue().build("reloadcerts"));
            } else {
                permissionsArray.add(entry.getValue().build());
            }
        }
        if (additionPerms.length != 0) {
            Stream.of(additionPerms).forEach(permissionsArray::add);
        }
        return permissionsArray;
    }
}
