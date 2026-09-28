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

package org.opensearch.security.api;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGINS_PREFIX;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotAllowed;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class FlushCacheApiIntegrationTest extends AbstractApiIntegrationTest {
    private final static String TEST_USER = "testuser";

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().build();

    private String cachePath() {
        return super.apiPath("cache");
    }

    private String cachePath(String user) {
        return super.apiPath("cache", "user", user);
    }

    @Override
    protected String apiPathPrefix() {
        return PLUGINS_PREFIX;
    }

    @Test
    public void testFlushCache() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.delete(cachePath()), isForbidden());
            assertThat(client.delete(cachePath(TEST_USER)), isForbidden());
        }
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            assertThat(client.get(cachePath()), isNotAllowed());
            assertThat(client.postJson(cachePath(), EMPTY_BODY), isNotAllowed());
            assertThat(client.putJson(cachePath(), EMPTY_BODY), isNotAllowed());

            final var deleteAllCacheResponse = client.delete(cachePath());
            assertThat(deleteAllCacheResponse, isOk());
            assertThat(
                deleteAllCacheResponse.getBody(),
                deleteAllCacheResponse.getTextFromJsonBody("/message"),
                is("Cache flushed successfully.")
            );

            final var deleteUserCacheResponse = client.delete(cachePath(TEST_USER));
            assertThat(deleteUserCacheResponse, isOk());
            assertThat(
                deleteUserCacheResponse.getBody(),
                deleteUserCacheResponse.getTextFromJsonBody("/message"),
                is("Cache invalidated for user: " + TEST_USER)
            );
        }
    }
}
