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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.oneOf;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.removeOp;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class ActionGroupsRestApiIntegrationTest extends AbstractConfigEntityApiIntegrationTest {

    private final static String REST_API_ADMIN_ACTION_GROUPS_ONLY = "rest_api_admin_action_groups_only";

    private final static String REST_ADMIN_PERMISSION_ACTION_GROUP = "rest-admin-permissions-action-group";

    /** Low cap so the over-limit case can be exercised with a four-entry body. Every other bulk request in this class stays within it. */
    private final static int BULK_MAX_ENTRIES = 3;

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().users(
        new TestSecurityConfig.User(REST_API_ADMIN_ACTION_GROUPS_ONLY).roles(
            new TestSecurityConfig.Role("rest_admin_role").clusterPermissions(restAdminPermission(Endpoint.ACTIONGROUPS))
        )
    )
        .nodeSettings(Map.of(ConfigConstants.SECURITY_RESTAPI_BULK_MAX_ENTRIES, BULK_MAX_ENTRIES))
        .actionGroups(
            new TestSecurityConfig.ActionGroup(
                REST_ADMIN_PERMISSION_ACTION_GROUP,
                TestSecurityConfig.ActionGroup.Type.INDEX,
                allRestAdminPermissions()
            )
        )
        .build();

    public ActionGroupsRestApiIntegrationTest() {
        super("actiongroups", new TestDescriptor() {
            @Override
            public String entityJsonProperty() {
                return "allowed_actions";
            }

            @Override
            public ToXContentObject entityPayload(final Boolean hidden, final Boolean reserved, final Boolean _static) {
                return actionGroup(hidden, reserved, _static, "a", "b");
            }

            @Override
            public ToXContentObject jsonPropertyPayload() {
                return configJsonArray("a", "b", "c");
            }

            @Override
            public Optional<String> restAdminLimitedUser() {
                return Optional.of(REST_API_ADMIN_ACTION_GROUPS_ONLY);
            }
        });
    }

    static ToXContentObject actionGroup(final String... allowedActions) {
        return actionGroup(null, null, allowedActions);
    }

    static ToXContentObject actionGroup(final Boolean hidden, final Boolean reserved, final String... allowedActions) {
        return actionGroup(hidden, reserved, null, allowedActions);
    }

    static ToXContentObject actionGroup(
        final Boolean hidden,
        final Boolean reserved,
        final Boolean _static,
        final String... allowedActions
    ) {
        return (builder, params) -> {
            builder.startObject();
            // TODO exclude in checking null value for the type
            builder.field("type", TestSecurityConfig.ActionGroup.Type.CLUSTER.type());
            if (allowedActions != null) {
                builder.field("allowed_actions");
                configJsonArray(allowedActions).toXContent(builder, params);
            } else {
                builder.startArray("allowed_actions").endArray();
            }
            if (reserved != null) {
                builder.field("reserved", reserved);
            }
            if (hidden != null) {
                builder.field("hidden", hidden);
            }
            if (_static != null) {
                builder.field("static", _static);
            }
            return builder.endObject();
        };
    }

    @Test
    public void forbiddenForRegularUsers() throws Exception {
        super.forbiddenForRegularUsers(localCluster);
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.putJson(apiPath(), actionGroups(Map.of("some_group", actionGroup("a")))), isForbidden());
        }
    }

    @Test
    public void availableForAdminUser() throws Exception {
        super.availableForAdminUser(localCluster);
    }

    @Test
    public void availableForTLSAdminUser() throws Exception {
        super.availableForTLSAdminUser(localCluster);
    }

    @Test
    public void availableForRESTAdminUser() throws Exception {
        super.availableForRESTAdminUser(localCluster);
    }

    @Test
    public void bulkPutCreatesAndUpdatesActionGroupsAtomically() throws Exception {
        final String first = "bulk_first_" + randomAlphanumericString();
        final String second = "bulk_second_" + randomAlphanumericString();
        final String third = "bulk_third_" + randomAlphanumericString();
        final String rejected = "bulk_rejected_" + randomAlphanumericString();
        final String referrer = "bulk_referrer_" + randomAlphanumericString();
        final String referee = "bulk_referee_" + randomAlphanumericString();

        try (TestRestClient client = localCluster.getRestClient(REST_ADMIN_USER)) {
            // mixed creates
            assertThat(client.putJson(apiPath(), actionGroups(Map.of(first, actionGroup("a", "b"), second, actionGroup("c")))), isOk());
            assertActionGroup(ok(() -> client.get(apiPath(first))), first, List.of("a", "b"));
            assertActionGroup(ok(() -> client.get(apiPath(second))), second, List.of("c"));

            // update one, create another; the omitted group is untouched
            assertThat(client.putJson(apiPath(), actionGroups(Map.of(first, actionGroup("a", "b", "x"), third, actionGroup("d")))), isOk());
            assertActionGroup(ok(() -> client.get(apiPath(first))), first, List.of("a", "b", "x"));
            assertActionGroup(ok(() -> client.get(apiPath(second))), second, List.of("c"));
            assertActionGroup(ok(() -> client.get(apiPath(third))), third, List.of("d"));

            // one entry named after an existing role rejects the whole request: the valid entry is not written
            assertThat(
                client.putJson(apiPath(), actionGroups(Map.of(rejected, actionGroup("e"), "kibana_user", actionGroup("f")))),
                isBadRequest("/message", "kibana_user is an existing role. A action group cannot be named with an existing role name.")
            );
            assertThat(client.get(apiPath(rejected)), isNotFound());

            // one self-referencing entry rejects the whole request
            assertThat(
                client.putJson(apiPath(), actionGroups(Map.of(rejected, actionGroup("e"), "self_ref", actionGroup("self_ref")))),
                isBadRequest("/message", "self_ref cannot be an allowed_action of itself")
            );
            assertThat(client.get(apiPath(rejected)), isNotFound());

            // one entry with an invalid type rejects the whole request
            final ToXContentObject invalidType = (builder, params) -> {
                builder.startObject().field("type", "asdasdsad").field("allowed_actions");
                configJsonArray("g").toXContent(builder, params);
                return builder.endObject();
            };
            assertThat(
                client.putJson(apiPath(), actionGroups(Map.of(rejected, actionGroup("e"), "bad_type", invalidType))),
                isBadRequest("/message", "Invalid action group type: asdasdsad. Supported types are: cluster, index.")
            );
            assertThat(client.get(apiPath(rejected)), isNotFound());

            // groups may reference other groups in the same request, in either order. Single PUT does not verify that a
            // referenced group exists, and FlattenedActionGroups tolerates unknown names and cycles at resolution time, so the
            // bulk path keeps that contract and the result cannot depend on entry order.
            final Map<String, ToXContentObject> referrerFirst = new LinkedHashMap<>();
            referrerFirst.put(referrer, actionGroup(referee));
            referrerFirst.put(referee, actionGroup("indices:data/read/search*"));
            assertThat(client.putJson(apiPath(), actionGroups(referrerFirst)), isOk());
            assertActionGroup(ok(() -> client.get(apiPath(referrer))), referrer, List.of(referee));
            assertActionGroup(ok(() -> client.get(apiPath(referee))), referee, List.of("indices:data/read/search*"));
            assertThat(client.delete(apiPath(referrer)), isOk());
            assertThat(client.delete(apiPath(referee)), isOk());

            final Map<String, ToXContentObject> refereeFirst = new LinkedHashMap<>();
            refereeFirst.put(referee, actionGroup("indices:data/read/search*"));
            refereeFirst.put(referrer, actionGroup(referee));
            assertThat(client.putJson(apiPath(), actionGroups(refereeFirst)), isOk());
            assertActionGroup(ok(() -> client.get(apiPath(referrer))), referrer, List.of(referee));
            assertActionGroup(ok(() -> client.get(apiPath(referee))), referee, List.of("indices:data/read/search*"));

            // a reference to a group that exists neither in the request nor in the configuration is accepted, as with single PUT
            assertThat(client.putJson(apiPath(), actionGroups(Map.of(rejected, actionGroup("does_not_exist_group")))), isOk());
            assertActionGroup(ok(() -> client.get(apiPath(rejected))), rejected, List.of("does_not_exist_group"));
            assertThat(client.delete(apiPath(rejected)), isOk());

            // more entries than the configured cap
            final Map<String, ToXContentObject> tooMany = Map.of(
                first,
                actionGroup("a"),
                second,
                actionGroup("b"),
                third,
                actionGroup("c"),
                rejected,
                actionGroup("d")
            );
            assertThat(
                client.putJson(apiPath(), actionGroups(tooMany)),
                isBadRequest("/message", "Request contains " + tooMany.size() + " resources; the maximum is " + BULK_MAX_ENTRIES + ".")
            );
            assertThat(client.get(apiPath(rejected)), isNotFound());
        }
    }

    static ToXContentObject actionGroups(final Map<String, ToXContentObject> actionGroups) {
        return (builder, params) -> {
            builder.startObject();
            for (final var actionGroup : actionGroups.entrySet()) {
                builder.field(actionGroup.getKey());
                actionGroup.getValue().toXContent(builder, params);
            }
            return builder.endObject();
        };
    }

    @Override
    void forbiddenToCreateEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {
        assertThat(client.putJson(apiPath("new_rest_admin_action_group"), actionGroup(randomRestAdminPermission())), isForbidden());
        assertThat(
            client.putJson(apiPath(), actionGroups(Map.of("new_bulk_rest_admin_action_group", actionGroup(randomRestAdminPermission())))),
            isForbidden()
        );
        assertThat(
            client.patch(apiPath(), patch(addOp("new_rest_admin_action_group", actionGroup(randomRestAdminPermission())))),
            isForbidden()
        );
    }

    @Override
    void forbiddenToUpdateAndDeleteExistingEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {
        // update
        assertThat(client.putJson(apiPath(REST_ADMIN_PERMISSION_ACTION_GROUP), actionGroup()), isForbidden());
        assertThat(
            client.putJson(apiPath(), actionGroups(Map.of(REST_ADMIN_PERMISSION_ACTION_GROUP, actionGroup("a", "b")))),
            isForbidden()
        );
        assertThat(client.patch(apiPath(), patch(replaceOp(REST_ADMIN_PERMISSION_ACTION_GROUP, actionGroup("a", "b")))), isForbidden());
        assertThat(
            client.patch(apiPath(REST_ADMIN_PERMISSION_ACTION_GROUP), patch(replaceOp("allowed_actions", configJsonArray("c", "d")))),
            isForbidden()
        );
        // remove
        assertThat(client.patch(apiPath(), patch(removeOp(REST_ADMIN_PERMISSION_ACTION_GROUP))), isForbidden());
        assertThat(client.patch(apiPath(REST_ADMIN_PERMISSION_ACTION_GROUP), patch(removeOp("allowed_actions"))), isForbidden());
        assertThat(client.delete(apiPath(REST_ADMIN_PERMISSION_ACTION_GROUP)), isForbidden());
    }

    @Override
    void verifySuperAdminCanCreateEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {
        assertThat(client.putJson(apiPath("new_rest_admin_action_group"), actionGroup(randomRestAdminPermission())), isCreated());
        assertThat(
            client.patch(apiPath(), patch(addOp("new_rest_admin_action_group_2", actionGroup(randomRestAdminPermission())))),
            isOk()
        );
    }

    @Override
    void verifySuperAdminCanUpdateAndDeleteEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {
        final var tempGroup = "temp_rest_admin_action_group";
        assertThat(client.putJson(apiPath(tempGroup), actionGroup(randomRestAdminPermission())), isCreated());
        assertThat(client.putJson(apiPath(tempGroup), actionGroup("a", "b")), isOk());
        assertThat(client.patch(apiPath(), patch(replaceOp(tempGroup, actionGroup("a", "b")))), isOk());
        assertThat(client.patch(apiPath(tempGroup), patch(replaceOp("allowed_actions", configJsonArray("c", "d")))), isOk());
        assertThat(client.delete(apiPath(tempGroup)), isOk());
    }

    @Override
    void verifyCrudOperations(final Boolean hidden, final Boolean reserved, final TestRestClient client) throws Exception {
        // create
        assertThat(client.putJson(apiPath("new_action_group"), actionGroup(hidden, reserved, "a", "b")), isCreated());
        var response = client.get(apiPath("new_action_group"));
        assertThat(response, isOk());
        assertActionGroup(response, "new_action_group", List.of("a", "b"));

        // update
        assertThat(client.putJson(apiPath("new_action_group"), actionGroup(hidden, reserved, "c", "d")), isOk());
        response = client.get(apiPath("new_action_group"));
        assertThat(response, isOk());
        assertActionGroup(response, "new_action_group", List.of("c", "d"));

        // delete
        assertThat(client.delete(apiPath("new_action_group")), isOk());
        response = client.get(apiPath("new_action_group"));
        assertThat(response, isNotFound());

        // patch add
        assertThat(client.patch(apiPath(), patch(addOp("new_action_group_for_patch", actionGroup(hidden, reserved, "e", "f")))), isOk());
        response = client.get(apiPath("new_action_group_for_patch"));
        assertThat(response, isOk());
        assertActionGroup(response, "new_action_group_for_patch", List.of("e", "f"));

        // patch replace
        assertThat(
            client.patch(apiPath("new_action_group_for_patch"), patch(replaceOp("allowed_actions", configJsonArray("g", "h")))),
            isOk()
        );
        response = client.get(apiPath("new_action_group_for_patch"));
        assertThat(response, isOk());
        assertActionGroup(response, "new_action_group_for_patch", List.of("g", "h"));

        // patch remove
        assertThat(client.patch(apiPath(), patch(removeOp("new_action_group_for_patch"))), isOk());
        response = client.get(apiPath("new_action_group_for_patch"));
        assertThat(response, isNotFound());
    }

    @Override
    void verifyBadRequestOperations(final TestRestClient client) throws Exception {
        // put
        assertThat(client.putJson(apiPath(), "{}"), isBadRequest());
        assertThat(client.putJson(apiPath(), "[]"), isBadRequest());
        assertThat(client.putJson(apiPath(), "{\"some_action_group\":\"not an object\"}"), isBadRequest());
        assertThat(client.putJson(apiPath(), actionGroups(Map.of("", actionGroup("a")))), isBadRequest());
        assertThat(client.putJson(apiPath("some_action_group"), EMPTY_BODY), isBadRequest());
        assertThat(
            client.putJson(apiPath("kibana_user"), actionGroup("a", "b")),
            isBadRequest("/message", "kibana_user is an existing role. A action group cannot be named with an existing role name.")
        );
        assertThat(
            client.putJson(apiPath("reference_itself"), actionGroup("reference_itself")),
            isBadRequest("/message", "reference_itself cannot be an allowed_action of itself")
        );
        assertThat(client.putJson(apiPath("some_action_group"), (builder, params) -> {
            builder.startObject().field("type", "asdasdsad").field("allowed_actions");
            configJsonArray("g", "f").toXContent(builder, params);
            return builder.endObject();
        }), isBadRequest("/message", "Invalid action group type: asdasdsad. Supported types are: cluster, index."));

        assertThat(
            client.putJson(apiPath("some_action_group"), configJsonArray("a", "b", "c")),
            isBadRequest("/missing_mandatory_keys/keys", "allowed_actions")
        );

        // duplicate check retained from original
        assertThat(
            client.putJson(apiPath("some_action_group"), configJsonArray("a", "b", "c")),
            isBadRequest("/missing_mandatory_keys/keys", "allowed_actions")
        );

        final ToXContentObject unknownJsonFields = (builder, params) -> {
            builder.startObject().field("a", "b").field("c", "d").field("allowed_actions");
            configJsonArray("g", "h").toXContent(builder, params);
            return builder.endObject();
        };
        assertThat(client.putJson(apiPath("some_action_group"), unknownJsonFields), isBadRequest("/invalid_keys/keys", "a,c"));

        assertThat(client.putJson(apiPath("some_action_group"), (builder, params) -> {
            builder.startObject().field("type", TestSecurityConfig.ActionGroup.Type.CLUSTER.type()).field("allowed_actions");
            configJsonArray("g", null, "f").toXContent(builder, params);
            return builder.endObject();
        }), isBadRequest("/reason", "`null` or blank values are not allowed as json array elements"));

        // patch
        assertThat(client.patch(apiPath("some_action_group"), EMPTY_BODY), isBadRequest());
        assertThat(client.patch(apiPath(), patch(addOp("some_action_group", EMPTY_BODY))), isBadRequest());
        assertThat(client.patch(apiPath(), patch(replaceOp("some_action_group", EMPTY_BODY))), isBadRequest());
        assertThat(
            client.patch(apiPath(), patch(addOp("kibana_user", actionGroup("a")))),
            isBadRequest("/message", "kibana_user is an existing role. A action group cannot be named with an existing role name.")
        );
        assertThat(
            client.patch(apiPath(), patch(addOp("reference_itself", actionGroup("reference_itself")))),
            isBadRequest("/message", "reference_itself cannot be an allowed_action of itself")
        );
        assertThat(
            client.patch(apiPath(), patch(addOp("some_action_group", configJsonArray("a", "b", "c")))),
            isBadRequest("/missing_mandatory_keys/keys", "allowed_actions")
        );

        assertThat(client.patch(apiPath(), patch(addOp("some_action_group", (ToXContentObject) (builder, params) -> {
            builder.startObject().field("type", "aaaa").field("allowed_actions");
            configJsonArray("g", "f").toXContent(builder, params);
            return builder.endObject();
        }))), isBadRequest());

        assertThat(client.patch(apiPath(), patch(addOp("some_action_group", (ToXContentObject) (builder, parameter) -> {
            builder.startObject();
            unknownJsonFields.toXContent(builder, parameter);
            return builder.endObject();
        }))), isBadRequest());

        assertThat(client.patch(apiPath(), patch(addOp("some_action_group", (ToXContentObject) (builder, params) -> {
            builder.startObject().field("type", TestSecurityConfig.ActionGroup.Type.CLUSTER.type()).field("allowed_actions");
            configJsonArray("g", null, "f").toXContent(builder, params);
            return builder.endObject();
        }))), isBadRequest("/reason", "`null` or blank values are not allowed as json array elements"));

        var response = client.patch(
            apiPath(),
            patch(
                addOp(
                    "some_action_group",
                    (ToXContentObject) (builder, params) -> builder.startObject().field("allowed_actions", "a").endObject()
                )
            )
        );
        assertThat(response, isBadRequest().withAttribute("/status", "error").withAttribute("/allowed_actions", "Array expected"));
    }

    void assertActionGroup(final TestRestClient.HttpResponse response, final String actionGroupName, final List<String> allowedActions) {
        assertThat(response.getBody(), not(response.getBooleanFromJsonBody("/" + actionGroupName + "/hidden")));
        assertThat(response.getBody(), not(response.getBooleanFromJsonBody("/" + actionGroupName + "/reserved")));
        assertThat(response.getBody(), not(response.getBooleanFromJsonBody("/" + actionGroupName + "/static")));
        assertThat(
            response.getBody(),
            response.getTextFromJsonBody("/" + actionGroupName + "/type"),
            oneOf(TestSecurityConfig.ActionGroup.Type.INDEX.type(), TestSecurityConfig.ActionGroup.Type.CLUSTER.type())
        );
        assertThat(response.getBody(), response.getTextArrayFromJsonBody("/" + actionGroupName + "/allowed_actions"), is(allowedActions));
    }

}
