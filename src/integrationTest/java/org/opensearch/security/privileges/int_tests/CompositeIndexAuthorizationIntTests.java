/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges.int_tests;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ActionType;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.ReadAccessContext;
import org.opensearch.action.support.ReadAccessPolicy;
import org.opensearch.action.support.ReadAccessPolicyService;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.common.xcontent.StatusToXContentObject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.tasks.Task;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestIndex;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.node.NodeClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class CompositeIndexAuthorizationIntTests {
    private static final String ACTION_NAME = "indices:data/read/mock_read_access/get";
    private static final TestIndex RESTRICTED_INDEX = TestIndex.name("policy_restricted").build();
    private static final TestIndex UNRESTRICTED_INDEX = TestIndex.name("policy_unrestricted").build();

    private static final TestSecurityConfig.User LIMITED_USER = new TestSecurityConfig.User("limited_user").roles(
        new TestSecurityConfig.Role("read_with_dls").indexPermissions(ACTION_NAME)
            .dls(QueryBuilders.termQuery("tenant", "blue"))
            .on(RESTRICTED_INDEX.name())
            .indexPermissions(ACTION_NAME)
            .on(UNRESTRICTED_INDEX.name())
    );
    private static final TestSecurityConfig.User UNRESTRICTED_USER = new TestSecurityConfig.User("unrestricted_user").roles(
        new TestSecurityConfig.Role("read_without_dls").indexPermissions(ACTION_NAME).on(RESTRICTED_INDEX.name(), UNRESTRICTED_INDEX.name())
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().singleNode()
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(LIMITED_USER, UNRESTRICTED_USER)
        .plugin(MockReadAccessPlugin.class)
        .build();

    @Test
    public void mockLogicalPlanRequestReceivesEffectiveDlsPolicy() {
        try (TestRestClient adminClient = cluster.getAdminCertRestClient()) {
            createIndex(adminClient, RESTRICTED_INDEX);
            createIndex(adminClient, UNRESTRICTED_INDEX);

            try (TestRestClient client = cluster.getRestClient(LIMITED_USER)) {
                TestRestClient.HttpResponse response = client.get(
                    "_mock/read_access/" + RESTRICTED_INDEX.name() + "," + UNRESTRICTED_INDEX.name()
                );

                assertThat(response, isOk());
                assertThat(response.getTextFromJsonBody("/has_restrictions"), is("true"));
                assertThat(response.getTextFromJsonBody("/restrictions/" + RESTRICTED_INDEX.name()), containsString("tenant"));
                assertThat(response.getTextFromJsonBody("/restrictions/" + RESTRICTED_INDEX.name()), containsString("blue"));
                assertThat(response.bodyAsJsonNode().get("restrictions").has(UNRESTRICTED_INDEX.name()), is(false));
            } finally {
                adminClient.delete(RESTRICTED_INDEX.name());
                adminClient.delete(UNRESTRICTED_INDEX.name());
            }
        }
    }

    @Test
    public void mockLogicalPlanRequestIsUnrestrictedWithoutDls() {
        try (TestRestClient adminClient = cluster.getAdminCertRestClient()) {
            createIndex(adminClient, RESTRICTED_INDEX);
            createIndex(adminClient, UNRESTRICTED_INDEX);

            try (TestRestClient client = cluster.getRestClient(UNRESTRICTED_USER)) {
                TestRestClient.HttpResponse response = client.get(
                    "_mock/read_access/" + RESTRICTED_INDEX.name() + "," + UNRESTRICTED_INDEX.name()
                );

                assertThat(response, isOk());
                assertThat(response.getTextFromJsonBody("/has_restrictions"), is("false"));
                assertThat(response.bodyAsJsonNode().get("restrictions").isEmpty(), is(true));
            } finally {
                adminClient.delete(RESTRICTED_INDEX.name());
                adminClient.delete(UNRESTRICTED_INDEX.name());
            }
        }
    }

    private static void createIndex(TestRestClient client, TestIndex index) {
        assertThat(client.putJson(index.name(), "{}"), isOk());
    }

    public static class MockReadAccessPlugin extends Plugin implements ActionPlugin {
        @Override
        public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
            return List.of(new ActionHandler<>(MockReadAccessAction.INSTANCE, TransportMockReadAccessAction.class));
        }

        @Override
        public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController restController,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster
        ) {
            return List.of(new MockReadAccessRestHandler());
        }
    }

    public static class MockReadAccessAction extends ActionType<MockReadAccessResponse> {
        private static final MockReadAccessAction INSTANCE = new MockReadAccessAction();

        private MockReadAccessAction() {
            super(ACTION_NAME, MockReadAccessResponse::new);
        }
    }

    public static class MockReadAccessRequest extends ActionRequest implements IndicesRequest.Replaceable {
        private String[] indices;

        public MockReadAccessRequest(String... indices) {
            this.indices = indices;
        }

        public MockReadAccessRequest(StreamInput in) throws IOException {
            super(in);
            indices = in.readStringArray();
        }

        @Override
        public String[] indices() {
            return indices;
        }

        @Override
        public MockReadAccessRequest indices(String... indices) {
            this.indices = indices;
            return this;
        }

        @Override
        public IndicesOptions indicesOptions() {
            return IndicesOptions.strictExpandOpen();
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeStringArray(indices);
        }
    }

    public static class MockReadAccessResponse extends ActionResponse implements StatusToXContentObject {
        private final Map<String, String> restrictions;

        public MockReadAccessResponse(Map<String, String> restrictions) {
            this.restrictions = Map.copyOf(restrictions);
        }

        public MockReadAccessResponse(StreamInput in) throws IOException {
            super(in);
            restrictions = in.readMap(StreamInput::readString, StreamInput::readString);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeMap(restrictions, StreamOutput::writeString, StreamOutput::writeString);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field("has_restrictions", restrictions.isEmpty() == false);
            builder.field("restrictions", restrictions);
            return builder.endObject();
        }

        @Override
        public RestStatus status() {
            return RestStatus.OK;
        }
    }

    public static class TransportMockReadAccessAction extends HandledTransportAction<MockReadAccessRequest, MockReadAccessResponse> {
        private final ReadAccessPolicyService readAccessPolicyService;

        @Inject
        public TransportMockReadAccessAction(
            TransportService transportService,
            ActionFilters actionFilters,
            ReadAccessPolicyService readAccessPolicyService
        ) {
            super(ACTION_NAME, transportService, actionFilters, MockReadAccessRequest::new);
            this.readAccessPolicyService = readAccessPolicyService;
        }

        @Override
        protected void doExecute(Task task, MockReadAccessRequest request, ActionListener<MockReadAccessResponse> listener) {
            ReadAccessPolicy policy = readAccessPolicyService.getReadAccessPolicy(ReadAccessContext.of(List.of(request.indices())));
            Map<String, String> restrictions = policy.coveredConcreteIndices()
                .stream()
                .filter(index -> policy.restrictionsForIndex(index).isPresent())
                .collect(
                    Collectors.toMap(
                        index -> index,
                        index -> Strings.toString(MediaTypeRegistry.JSON, policy.restrictionsForIndex(index).orElseThrow())
                    )
                );
            listener.onResponse(new MockReadAccessResponse(restrictions));
        }
    }

    public static class MockReadAccessRestHandler extends BaseRestHandler {
        @Override
        public String getName() {
            return "mock_read_access";
        }

        @Override
        public List<Route> routes() {
            return List.of(new Route(GET, "/_mock/read_access/{indices}"));
        }

        @Override
        protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
            MockReadAccessRequest mockRequest = new MockReadAccessRequest(request.param("indices").split(","));
            return channel -> client.execute(MockReadAccessAction.INSTANCE, mockRequest, new RestToXContentListener<>(channel));
        }
    }
}
