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
import static org.opensearch.security.dlic.rest.support.Utils.PLUGINS_PREFIX;

public class FlushCacheApiIntegrationTest extends AbstractApiIntegrationTest {
    private final static String TEST_USER = "testuser";

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
        withUser(NEW_USER, client -> {
            forbidden(() -> client.delete(cachePath()));
            forbidden(() -> client.delete(cachePath(TEST_USER)));
        });
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), client -> {
            methodNotAllowed(() -> client.get(cachePath()));
            methodNotAllowed(() -> client.postJson(cachePath(), EMPTY_BODY));
            methodNotAllowed(() -> client.putJson(cachePath(), EMPTY_BODY));
            final var deleteAllCacheResponse = ok(() -> client.delete(cachePath()));
            assertThat(
                deleteAllCacheResponse.getBody(),
                deleteAllCacheResponse.getTextFromJsonBody("/message"),
                is("Cache flushed successfully.")
            );
            final var deleteUserCacheResponse = ok(() -> client.delete(cachePath(TEST_USER)));
            assertThat(
                deleteUserCacheResponse.getBody(),
                deleteUserCacheResponse.getTextFromJsonBody("/message"),
                is("Cache invalidated for user: " + TEST_USER)
            );
        });
    }
}
