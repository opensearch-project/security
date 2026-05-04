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

package org.opensearch.security.action.apitokens;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;

public class ApiTokenTest {

    @Test
    public void testApiTokenRoundTrip() throws IOException {
        long expiration = 9999999999L;
        Instant creationTime = Instant.ofEpochMilli(1700000000000L);
        ApiToken original = new ApiToken(
            "my-token",
            ApiTokenRepository.hashToken("os_my_token"),
            List.of("cluster:monitor", "cluster:admin"),
            List.of(new ApiToken.IndexPermission(List.of("logs-*"), List.of("read", "write"))),
            creationTime,
            expiration,
            null,
            "admin"
        );

        String json = original.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS).toString();

        XContentParser parser = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, json);

        ApiToken parsed = ApiToken.fromXContent(parser);

        assertEquals(original.getName(), parsed.getName());
        assertEquals(original.getClusterPermissions(), parsed.getClusterPermissions());
        assertEquals(original.getExpiration(), parsed.getExpiration());
        assertEquals(creationTime, parsed.getCreationTime());
        assertEquals("admin", parsed.getCreatedBy());
        assertEquals(1, parsed.getIndexPermissions().size());
        assertThat(parsed.getIndexPermissions().get(0).getIndexPatterns(), equalTo(List.of("logs-*")));
        assertThat(parsed.getIndexPermissions().get(0).getAllowedActions(), equalTo(List.of("read", "write")));
    }

    @Test
    public void testIndexPermissionToStringFromString() throws IOException {
        String indexPermissionString = "{\"index_pattern\":[\"index1\",\"index2\"],\"allowed_actions\":[\"action1\",\"action2\"]}";
        ApiToken.IndexPermission indexPermission = new ApiToken.IndexPermission(
            Arrays.asList("index1", "index2"),
            Arrays.asList("action1", "action2")
        );
        assertThat(
            indexPermission.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS).toString(),
            equalTo(indexPermissionString)
        );

        XContentParser parser = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, indexPermissionString);

        ApiToken.IndexPermission indexPermissionFromString = ApiToken.IndexPermission.fromXContent(parser);
        assertThat(indexPermissionFromString.getIndexPatterns(), equalTo(List.of("index1", "index2")));
        assertThat(indexPermissionFromString.getAllowedActions(), equalTo(List.of("action1", "action2")));
    }

}
