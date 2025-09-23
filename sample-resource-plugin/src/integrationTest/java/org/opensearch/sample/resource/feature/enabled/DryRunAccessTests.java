/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled;

import java.util.List;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_REVOKE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.revokeAccessPayload;
import static org.opensearch.sample.resource.TestUtils.sampleAllAG;
import static org.opensearch.sample.resource.TestUtils.sampleReadOnlyAG;
import static org.opensearch.sample.resource.TestUtils.shareWithPayload;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run simulation on resource access
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DryRunAccessTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

    private String adminResId;

    @Before
    public void setup() {
        adminResId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(adminResId); // wait until sharing entry is created
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    @Test
    public void testPluginInstalledCorrectly() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse plugins = client.get("_cat/plugins");
            assertThat(plugins.getBody(), containsString("OpenSearchSecurityPlugin"));
            assertThat(plugins.getBody(), containsString("SampleResourcePlugin"));
        }
    }

    @Test
    public void testResourceSharingIndexExists() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse resp = client.get(RESOURCE_SHARING_INDEX + "/_search");
            resp.assertStatusCode(HttpStatus.SC_OK);
        }
    }

    @Test
    public void testDryRunAccess() {
        // user has no permission

        // cannot create own resource
        try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
            String sample = "{\"name\":\"sampleUser\"}";
            HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT + "?perform_permission_check=true", sample);
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(false));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of("cluster:admin/sample-resource-plugin/create")));

            resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId + "?perform_permission_check=true");
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(false));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of("cluster:admin/sample-resource-plugin/get")));
        }

        // share resource at readonly level with no_access_user
        api.assertApiShare(adminResId, USER_ADMIN, NO_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_OK);

        try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
            // recheck read access
            HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId + "?perform_permission_check=true");
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(true));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of()));

            // cannot update resource
            String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
            resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + adminResId + "?perform_permission_check=true", updatePayload);
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(false));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of("cluster:admin/sample-resource-plugin/update")));

            // cannot share resource
            resp = client.postJson(
                SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + adminResId + "?perform_permission_check=true",
                shareWithPayload(FULL_ACCESS_USER.getName(), sampleReadOnlyAG.name())
            );
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(false));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of("cluster:admin/sample-resource-plugin/share")));

            // cannot revoke resource access
            resp = client.postJson(
                SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + adminResId + "?perform_permission_check=true",
                revokeAccessPayload(FULL_ACCESS_USER.getName(), sampleReadOnlyAG.name())
            );
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(false));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of("cluster:admin/sample-resource-plugin/revoke")));

            // cannot delete resource
            resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + adminResId + "?perform_permission_check=true");
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(false));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of("cluster:admin/sample-resource-plugin/delete")));
        }

        // share resource at full-access level with no_access_user
        api.assertApiShare(adminResId, USER_ADMIN, NO_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_OK);

        // user will now also be able to update, share, revoke and delete resource
        try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
            // read simulation
            HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId + "?perform_permission_check=true");
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(true));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of()));

            // can update resource
            String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
            resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + adminResId + "?perform_permission_check=true", updatePayload);
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(true));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of()));

            // can share resource
            resp = client.postJson(
                SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + adminResId + "?perform_permission_check=true",
                shareWithPayload(FULL_ACCESS_USER.getName(), sampleReadOnlyAG.name())
            );
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(true));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of()));

            // can revoke resource access
            resp = client.postJson(
                SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + adminResId + "?perform_permission_check=true",
                revokeAccessPayload(FULL_ACCESS_USER.getName(), sampleReadOnlyAG.name())
            );
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(true));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of()));

            // can delete resource
            resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + adminResId + "?perform_permission_check=true");
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.bodyAsMap().get("accessAllowed"), equalTo(true));
            assertThat(resp.bodyAsMap().get("missingPrivileges"), equalTo(List.of()));
        }
    }

}
