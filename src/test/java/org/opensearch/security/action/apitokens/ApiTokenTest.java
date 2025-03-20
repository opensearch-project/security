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
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import org.mockito.Mock;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ApiTokenTest {

    @Mock
    private Client client;

    @Mock
    private IndicesAdminClient indicesAdminClient;

    @Mock
    private ClusterService clusterService;

    @Mock
    private Metadata metadata;

    private ApiTokenIndexHandler indexHandler;

    @Before
    public void setup() {

        client = mock(Client.class, RETURNS_DEEP_STUBS);
        indicesAdminClient = mock(IndicesAdminClient.class);
        clusterService = mock(ClusterService.class, RETURNS_DEEP_STUBS);
        metadata = mock(Metadata.class);

        when(client.admin().indices()).thenReturn(indicesAdminClient);

        when(clusterService.state().metadata()).thenReturn(metadata);

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        when(client.threadPool().getThreadContext()).thenReturn(threadContext);

        indexHandler = new ApiTokenIndexHandler(client, clusterService);
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
