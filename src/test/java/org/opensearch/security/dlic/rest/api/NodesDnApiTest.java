/*
 * Portions Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.support.ConfigConstants;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.test.helper.file.FileHelper;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.Assert;
import com.google.common.collect.ImmutableList;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@RunWith(Parameterized.class)
public class NodesDnApiTest extends AbstractRestApiUnitTest {
    private HttpResponse response;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final String ENDPOINT;

    public NodesDnApiTest(String endpoint){
        ENDPOINT = endpoint;
    }

    @Parameterized.Parameters
    public static Iterable<String> endpoints() {
        return ImmutableList.of(
                "/_opendistro/_security/api",
                "/_plugins/_security/api"
        );
    }

    private <T> JsonNode asJsonNode(T t) throws Exception {
        return OBJECT_MAPPER.readTree(OBJECT_MAPPER.writeValueAsString(t));
    }

    private Map<String, List<String>> nodesDnEntry(String...nodesDn) {
        return ImmutableMap.of("nodes_dn", Arrays.asList(nodesDn));
    }

    private void testCrudScenarios(final int expectedStatus, final Header... headers) throws Exception {
        response = rh.executeGetRequest(ENDPOINT + "/nodesdn?show_all=true", headers);
        assertThat(response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            JsonNode expected = asJsonNode(ImmutableMap.of(
                "cluster1", nodesDnEntry("cn=popeye"),
                 NodesDnApiAction.STATIC_OPENSEARCH_YML_NODES_DN, nodesDnEntry("CN=example.com")));

            JsonNode node = OBJECT_MAPPER.readTree(response.getBody());
            assertThat(node, equalTo(asJsonNode(expected)));
        }

        response = rh.executeGetRequest(ENDPOINT + "/nodesdn?show_all=false", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            JsonNode expected = asJsonNode(ImmutableMap.of("cluster1", nodesDnEntry("cn=popeye")));
            JsonNode node = OBJECT_MAPPER.readTree(response.getBody());
            assertThat(node, equalTo(asJsonNode(expected)));
        }

        response = rh.executeGetRequest(ENDPOINT + "/nodesdn", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            JsonNode expected = asJsonNode(ImmutableMap.of("cluster1", nodesDnEntry("cn=popeye")));
            JsonNode node = OBJECT_MAPPER.readTree(response.getBody());
            assertThat(node, equalTo(asJsonNode(expected)));
        }

        response = rh.executeGetRequest(ENDPOINT + "/nodesdn/cluster1", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            JsonNode expected = asJsonNode(ImmutableMap.of("cluster1", nodesDnEntry("cn=popeye")));
            JsonNode node = OBJECT_MAPPER.readTree(response.getBody());
            assertThat(node, equalTo(asJsonNode(expected)));
        }

        response = rh.executePutRequest(ENDPOINT + "/nodesdn/cluster1", "{\"nodes_dn\": [\"cn=popeye\"]}", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

        response = rh.executePatchRequest(ENDPOINT + "/nodesdn/cluster1", "[{ \"op\": \"add\", \"path\": \"/nodes_dn/-\", \"value\": \"bluto\" }]", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

        response = rh.executePatchRequest(ENDPOINT + "/nodesdn", "[{ \"op\": \"remove\", \"path\": \"/cluster1/nodes_dn/0\"}]", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

        response = rh.executeDeleteRequest(ENDPOINT + "/nodesdn/cluster1", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
    }

    @Test
    public void testNodesDnApiWithDynamicConfigDisabled() throws Exception {
        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        testCrudScenarios(HttpStatus.SC_BAD_REQUEST);
    }

    @Test
    public void testNodesDnApi() throws Exception {

        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, true)
            .putList(ConfigConstants.SECURITY_NODES_DN, "CN=example.com")
            .build();
        setupWithRestRoles(settings);

        final Header adminCredsHeader = encodeBasicHeader("admin", "admin");
        final Header nonAdminCredsHeader = encodeBasicHeader("sarek", "sarek");

        {
            // No creds, no admin certificate - UNAUTHORIZED
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = false;
            testCrudScenarios(HttpStatus.SC_UNAUTHORIZED);
        }

        {
            // admin creds, no admin certificate - FORBIDDEN
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = false;
            testCrudScenarios(HttpStatus.SC_FORBIDDEN, adminCredsHeader);
        }

        {
            // any creds, admin certificate - OK
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = true;
            testCrudScenarios(HttpStatus.SC_OK, nonAdminCredsHeader);
        }

        {
            // any creds, admin certificate, disallowed key - FORBIDDEN
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = true;

            final int expectedStatus = HttpStatus.SC_FORBIDDEN;

            response = rh.executePutRequest(ENDPOINT + "/nodesdn/" + NodesDnApiAction.STATIC_OPENSEARCH_YML_NODES_DN, "{\"nodes_dn\": [\"cn=popeye\"]}", nonAdminCredsHeader);
            assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

            response = rh.executePatchRequest(ENDPOINT + "/nodesdn/" + NodesDnApiAction.STATIC_OPENSEARCH_YML_NODES_DN,
                "[{ \"op\": \"add\", \"path\": \"/nodes_dn/-\", \"value\": \"bluto\" }]" , nonAdminCredsHeader);
            assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

            response = rh.executeDeleteRequest(ENDPOINT + "/nodesdn/" + NodesDnApiAction.STATIC_OPENSEARCH_YML_NODES_DN, nonAdminCredsHeader);
            assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        }
    }

    @Test
    public void testNodesDnApiAuditComplianceLogging() throws Exception {

        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, true)
            .putList(ConfigConstants.SECURITY_NODES_DN, "CN=example.com")
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .build();
        setupWithRestRoles(settings);
        TestAuditlogImpl.clear();

        final Header nonAdminCredsHeader = encodeBasicHeader("sarek", "sarek");

        {
            // any creds, admin certificate - OK
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = true;
            testCrudScenarios(HttpStatus.SC_OK, nonAdminCredsHeader);
        }

        System.out.println(TestAuditlogImpl.sb.toString());

        final Map<AuditCategory, Long> expectedCategoryCounts = ImmutableMap.of(
            AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ, 4L,
            AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE, 4L);
        Map<AuditCategory, Long> actualCategoryCounts = TestAuditlogImpl.messages.stream().collect(Collectors.groupingBy(AuditMessage::getCategory, Collectors.counting()));

        assertThat(actualCategoryCounts, equalTo(expectedCategoryCounts));
    }

    @Test
    public void checkNullElementsInArray() throws Exception{
        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        String body = FileHelper.loadFile("restapi/nodesdn_null_array_element.json");
        HttpResponse response = rh.executePutRequest(ENDPOINT+ "/nodesdn", body, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }
}
