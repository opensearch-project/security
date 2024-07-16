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

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class FlushCacheApiIntegrationTest extends AbstractApiIntegrationTest {
    private final static String TEST_USER = "testuser";

    private String cachePath() {
        return super.apiPath("cache");
    }

    private String cachePath(String user) {
        return super.apiPath("cache", "user", user);
    }

    @Test
    public void testFlushCache() throws Exception {
        withUser(NEW_USER, client -> {
            forbidden(() -> client.get(cachePath()));
            forbidden(() -> client.postJson(cachePath(), EMPTY_BODY));
            forbidden(() -> client.putJson(cachePath(), EMPTY_BODY));
            forbidden(() -> client.delete(cachePath()));
            forbidden(() -> client.delete(cachePath(TEST_USER)));
        });
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> {
            notImplemented(() -> client.get(cachePath()));
            notImplemented(() -> client.postJson(cachePath(), EMPTY_BODY));
            notImplemented(() -> client.putJson(cachePath(), EMPTY_BODY));
            final var deleteAllCacheResponse = ok(() -> client.delete(cachePath()));
            assertThat(
                deleteAllCacheResponse.getBody(),
                deleteAllCacheResponse.getTextFromJsonBody("/message"),
                is("Cache flushed successfully.")
            );
            final var deleteUserCacheResponse = ok(() -> client.delete(cachePath(TEST_USER)));
            assertThat(
                deleteUserCacheResponse.getBody(),
                deleteAllCacheResponse.getTextFromJsonBody("/message"),
                is("Cache invalidated for user: " + TEST_USER)
            );
        });
    }
}
