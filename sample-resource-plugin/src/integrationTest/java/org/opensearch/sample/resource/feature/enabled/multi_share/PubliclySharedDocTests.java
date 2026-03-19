/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled.multi_share;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Tests for general_access (public) sharing at a specific access level.
 * Verifies that general_access grants everyone the specified level,
 * while named recipients can hold higher levels independently.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class PubliclySharedDocTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
    private String resourceId;

    @Before
    public void setup() {
        resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    @Test
    public void generalAccess_readOnly_grantsEveryoneReadAccess() throws Exception {
        // no access before sharing
        forbidden(() -> api.getResource(resourceId, FULL_ACCESS_USER));
        forbidden(() -> api.getResource(resourceId, LIMITED_ACCESS_USER));
        forbidden(() -> api.getResource(resourceId, NO_ACCESS_USER));

        ok(() -> api.shareResourceGenerally(resourceId, USER_ADMIN, SAMPLE_READ_ONLY));

        // everyone can read
        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, FULL_ACCESS_USER));
        assertThat(response.getBody(), containsString("sample"));

        response = ok(() -> api.getResource(resourceId, LIMITED_ACCESS_USER));
        assertThat(response.getBody(), containsString("sample"));

        // but no one can write
        forbidden(() -> api.updateResource(resourceId, FULL_ACCESS_USER, "updated"));
        forbidden(() -> api.deleteResource(resourceId, FULL_ACCESS_USER));
    }

    @Test
    public void generalAccess_fullAccess_grantsEveryoneFullAccess() throws Exception {
        forbidden(() -> api.getResource(resourceId, LIMITED_ACCESS_USER));

        ok(() -> api.shareResourceGenerally(resourceId, USER_ADMIN, SAMPLE_FULL_ACCESS));

        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, LIMITED_ACCESS_USER));
        assertThat(response.getBody(), containsString("sample"));

        ok(() -> api.updateResource(resourceId, LIMITED_ACCESS_USER, "updated"));
        ok(() -> api.deleteResource(resourceId, LIMITED_ACCESS_USER));
    }

    @Test
    public void generalAccess_readOnly_namedRecipientCanWrite() throws Exception {
        // share publicly at read-only, but grant FULL_ACCESS_USER write access explicitly
        ok(() -> api.shareResourceGenerally(resourceId, USER_ADMIN, SAMPLE_READ_ONLY));
        ok(() -> api.shareResource(resourceId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_FULL_ACCESS));

        // everyone can read
        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, LIMITED_ACCESS_USER));
        assertThat(response.getBody(), containsString("sample"));

        // only FULL_ACCESS_USER can write
        ok(() -> api.updateResource(resourceId, FULL_ACCESS_USER, "updated"));
        forbidden(() -> api.updateResource(resourceId, LIMITED_ACCESS_USER, "updated"));
        forbidden(() -> api.deleteResource(resourceId, LIMITED_ACCESS_USER));
    }

    @Test
    public void revokeGeneralAccess_removesPublicAccess() throws Exception {
        ok(() -> api.shareResourceGenerally(resourceId, USER_ADMIN, SAMPLE_READ_ONLY));

        // confirm access granted
        ok(() -> api.getResource(resourceId, FULL_ACCESS_USER));

        // revoke general access
        ok(() -> api.revokeGeneralAccess(resourceId, USER_ADMIN, SAMPLE_READ_ONLY));

        // access should be gone
        forbidden(() -> api.getResource(resourceId, FULL_ACCESS_USER));
    }

    @Test
    public void generalAccess_doesNotLeakSharingInfo() throws Exception {
        ok(() -> api.shareResourceGenerally(resourceId, USER_ADMIN, SAMPLE_READ_ONLY));

        // a user with only general read access cannot view or modify sharing info
        forbidden(() -> api.shareResource(resourceId, FULL_ACCESS_USER, FULL_ACCESS_USER, SAMPLE_FULL_ACCESS));
        forbidden(() -> api.revokeGeneralAccess(resourceId, FULL_ACCESS_USER, SAMPLE_READ_ONLY));
    }

    @Test
    public void generalAccess_upgradeLevel_replacesExistingGeneralAccess() throws Exception {
        ok(() -> api.shareResourceGenerally(resourceId, USER_ADMIN, SAMPLE_READ_ONLY));
        forbidden(() -> api.updateResource(resourceId, FULL_ACCESS_USER, "updated"));

        // upgrade general access to full
        ok(() -> api.shareResourceGenerally(resourceId, USER_ADMIN, SAMPLE_FULL_ACCESS));

        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, FULL_ACCESS_USER));
        assertThat(response.getBody(), containsString("sample"));
        ok(() -> api.updateResource(resourceId, FULL_ACCESS_USER, "updated"));
    }

    @Test
    public void generalAccess_sharingInfoResponse_containsGeneralAccessField() throws Exception {
        ok(() -> api.shareResourceGenerally(resourceId, USER_ADMIN, SAMPLE_READ_ONLY));

        try (var client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = ok(
                () -> client.get(
                    TestUtils.SECURITY_SHARE_ENDPOINT
                        + "?resource_id="
                        + resourceId
                        + "&resource_type="
                        + org.opensearch.sample.utils.Constants.RESOURCE_TYPE
                )
            );
            assertThat(response.getBody(), containsString("general_access"));
            assertThat(response.getBody(), containsString(SAMPLE_READ_ONLY));
            assertThat(response.getBody(), not(containsString("\"users\"")));
        }
    }
}
