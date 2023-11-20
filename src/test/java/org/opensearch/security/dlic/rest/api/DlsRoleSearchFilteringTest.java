/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.dlic.rest.api;

import java.util.stream.IntStream;

import org.apache.hc.core5.http.HttpStatus;
import org.junit.Test;

import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class DlsRoleSearchFilteringTest extends AbstractRestApiUnitTest {
    private final String SECURITY_ENDPOINT;

    public DlsRoleSearchFilteringTest() {
        SECURITY_ENDPOINT = PLUGINS_PREFIX + "/api";
    }

    @Test
    public void testRoleUnionSearchFiltering() throws Exception {
        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // create roles
        final String ROLE_ENDPOINT = SECURITY_ENDPOINT + "/roles";
        RestHelper.HttpResponse testRoleOneResponse = rh.executePutRequest(
            ROLE_ENDPOINT + "/test_role_1",
            "{\"cluster_permissions\":[\"cluster_all\"],\"index_permissions\":[{\"index_patterns\":[\"*\"],\"dls\":\"{\\\"bool\\\":{\\\"must_not\\\":{\\\"match\\\":{\\\"sensitive\\\":true}}}}\",\"fls\":[],\"masked_fields\":[],\"allowed_actions\":[\"read\",\"indices:admin/get\"]}],\"tenant_permissions\":[{\"tenant_patterns\":[\"global_tenant\"],\"allowed_actions\":[\"kibana_all_read\"]}]}"
        );
        RestHelper.HttpResponse testRoleTwoResponse = rh.executePutRequest(
            ROLE_ENDPOINT + "/test_role_2",
            "{\"cluster_permissions\":[\"cluster_all\"],\"index_permissions\":[{\"index_patterns\":[\"my_index*\"],\"dls\":\"{\\\"bool\\\":{\\\"must\\\":{\\\"match\\\":{\\\"genre\\\":\\\"History\\\"}}}}\",\"fls\":[],\"masked_fields\":[],\"allowed_actions\":[\"indices_all\"]}],\"tenant_permissions\":[{\"tenant_patterns\":[\"global_tenant\"],\"allowed_actions\":[\"kibana_all_read\"]}]}"
        );
        assertThat(testRoleOneResponse.getStatusCode(), equalTo(HttpStatus.SC_CREATED));
        assertThat(testRoleTwoResponse.getStatusCode(), equalTo(HttpStatus.SC_CREATED));

        // create user w/ no roles mapped at first
        final String USER_ENDPOINT = SECURITY_ENDPOINT + "/internalusers/newuser";
        RestHelper.HttpResponse newUserResponse = rh.executePutRequest(
            USER_ENDPOINT,
            "{\"password\":\"Admin22222!!\",\"opendistro_security_roles\":[],\"backend_roles\":[],\"attributes\":{}}"
        );
        assertThat(newUserResponse.getStatusCode(), equalTo(HttpStatus.SC_CREATED));

        // create index
        final String INDEX_ENDPOINT = "/my_index1";
        RestHelper.HttpResponse createIndexResponse = rh.executePutRequest(
            INDEX_ENDPOINT,
            "{\"settings\":{\"number_of_shards\":6,\"number_of_replicas\":2}}",
            AbstractSecurityUnitTest.encodeBasicHeader("admin", "admin")
        );
        assertThat(createIndexResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // create test documents
        String[] documents = new String[] {
            "{\"genre\":\"History\",\"date\":\"01-01-2020\",\"sensitive\":true}",
            "{\"genre\":\"Math\",\"date\":\"01-01-2020\",\"sensitive\":true}",
            "{\"genre\":\"History\",\"date\":\"01-01-2020\",\"sensitive\":true}",
            "{\"genre\":\"Math\",\"date\":\"01-01-2020\",\"sensitive\":true}",
            "{\"genre\":\"History\",\"date\":\"01-01-2020\",\"sensitive\":true}",
            "{\"genre\":\"Math\",\"date\":\"01-01-2020\",\"sensitive\":false}",
            "{\"genre\":\"History\",\"date\":\"01-01-2020\",\"sensitive\":false}",
            "{\"genre\":\"Math\",\"date\":\"01-01-2020\",\"sensitive\":false}",
            "{\"genre\":\"History\",\"date\":\"01-01-2020\",\"sensitive\":false}",
            "{\"genre\":\"Math\",\"date\":\"01-01-2020\",\"sensitive\":false}" };
         IntStream.range(1, documents.length + 1).forEach(i -> {
            RestHelper.HttpResponse createDocumentResponse = rh.executePutRequest(
                INDEX_ENDPOINT + "/_doc/" + i,
                documents[i - 1],
                AbstractSecurityUnitTest.encodeBasicHeader("admin", "admin")
            );
            assertThat(createDocumentResponse.getStatusCode(), equalTo(HttpStatus.SC_CREATED));
        });

        RestHelper.HttpResponse testResponse = rh.executeGetRequest(INDEX_ENDPOINT + "/_search", "{\"query\":{\"match_all\":{}}}");
        System.out.println(testResponse.getBody());
    }
}
