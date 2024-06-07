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

import java.util.List;
import java.util.Optional;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.oneOf;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.removeOp;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;

public class ActionGroupsRestApiIntegrationTest extends AbstractConfigEntityApiIntegrationTest {

    private final static String REST_API_ADMIN_ACTION_GROUPS_ONLY = "rest_api_admin_action_groups_only";

    private final static String REST_ADMIN_PERMISSION_ACTION_GROUP = "rest-admin-permissions-action-group";

    static {
        testSecurityConfig.withRestAdminUser(REST_API_ADMIN_ACTION_GROUPS_ONLY, restAdminPermission(Endpoint.ACTIONGROUPS))
            .actionGroups(
                new TestSecurityConfig.ActionGroup(
                    REST_ADMIN_PERMISSION_ACTION_GROUP,
                    TestSecurityConfig.ActionGroup.Type.INDEX,
                    allRestAdminPermissions()
                )
            );
    }

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
                return allowedActionsArray("a", "b", "c");
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
            builder.field("type", randomType());
            if (allowedActions != null) {
                builder.field("allowed_actions");
                allowedActionsArray(allowedActions).toXContent(builder, params);
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

    static String randomType() {
        return randomFrom(List.of(TestSecurityConfig.ActionGroup.Type.CLUSTER.type(), TestSecurityConfig.ActionGroup.Type.INDEX.type()));
    }

    static ToXContentObject allowedActionsArray(final String... allowedActions) {
        return (builder, params) -> {
            builder.startArray();
            for (final var allowedAction : allowedActions) {
                if (allowedAction == null) {
                    builder.nullValue();
                } else {
                    builder.value(allowedAction);
                }
            }
            return builder.endArray();
        };
    }

    @Override
    void forbiddenToCreateEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {
        forbidden(() -> client.putJson(apiPath("new_rest_admin_action_group"), actionGroup(randomRestAdminPermission())));
        forbidden(() -> client.patch(apiPath(), patch(addOp("new_rest_admin_action_group", actionGroup(randomRestAdminPermission())))));
    }

    @Override
    void forbiddenToUpdateAndDeleteExistingEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {
        // update
        forbidden(() -> client.putJson(apiPath(REST_ADMIN_PERMISSION_ACTION_GROUP), actionGroup()));
        forbidden(() -> client.patch(apiPath(), patch(replaceOp(REST_ADMIN_PERMISSION_ACTION_GROUP, actionGroup("a", "b")))));
        forbidden(
            () -> client.patch(
                apiPath(REST_ADMIN_PERMISSION_ACTION_GROUP),
                patch(replaceOp("allowed_actions", allowedActionsArray("c", "d")))
            )
        );
        // remove
        forbidden(() -> client.patch(apiPath(), patch(removeOp(REST_ADMIN_PERMISSION_ACTION_GROUP))));
        forbidden(() -> client.patch(apiPath(REST_ADMIN_PERMISSION_ACTION_GROUP), patch(removeOp("allowed_actions"))));
        forbidden(() -> client.delete(apiPath(REST_ADMIN_PERMISSION_ACTION_GROUP)));
    }

    @Override
    void verifyCrudOperations(final Boolean hidden, final Boolean reserved, final TestRestClient client) throws Exception {
        created(() -> client.putJson(apiPath("new_action_group"), actionGroup(hidden, reserved, "a", "b")));
        assertActionGroup(ok(() -> client.get(apiPath("new_action_group"))), "new_action_group", List.of("a", "b"));

        ok(() -> client.putJson(apiPath("new_action_group"), actionGroup(hidden, reserved, "c", "d")));
        assertActionGroup(ok(() -> client.get(apiPath("new_action_group"))), "new_action_group", List.of("c", "d"));

        ok(() -> client.delete(apiPath("new_action_group")));
        notFound(() -> client.get(apiPath("new_action_group")));

        ok(() -> client.patch(apiPath(), patch(addOp("new_action_group_for_patch", actionGroup(hidden, reserved, "e", "f")))));
        assertActionGroup(ok(() -> client.get(apiPath("new_action_group_for_patch"))), "new_action_group_for_patch", List.of("e", "f"));

        ok(() -> client.patch(apiPath("new_action_group_for_patch"), patch(replaceOp("allowed_actions", allowedActionsArray("g", "h")))));
        assertActionGroup(ok(() -> client.get(apiPath("new_action_group_for_patch"))), "new_action_group_for_patch", List.of("g", "h"));

        ok(() -> client.patch(apiPath(), patch(removeOp("new_action_group_for_patch"))));
        notFound(() -> client.get(apiPath("new_action_group_for_patch")));
    }

    @Override
    void verifyBadRequestOperations(final TestRestClient client) throws Exception {
        // put
        badRequest(() -> client.putJson(apiPath("some_action_group"), EMPTY_BODY));
        badRequestWithMessage(
            () -> client.putJson(apiPath("kibana_user"), actionGroup("a", "b")),
            "kibana_user is an existing role. A action group cannot be named with an existing role name."
        );
        badRequestWithMessage(
            () -> client.putJson(apiPath("reference_itself"), actionGroup("reference_itself")),
            "reference_itself cannot be an allowed_action of itself"
        );

        badRequestWithMessage(() -> client.putJson(apiPath("some_action_group"), (builder, params) -> {
            builder.startObject().field("type", "asdasdsad").field("allowed_actions");
            allowedActionsArray("g", "f").toXContent(builder, params);
            return builder.endObject();
        }), "Invalid action group type: asdasdsad. Supported types are: cluster, index.");

        assertMissingMandatoryKeys(
            badRequest(() -> client.putJson(apiPath("some_action_group"), allowedActionsArray("a", "b", "c"))),
            "allowed_actions"
        );

        assertMissingMandatoryKeys(
            badRequest(() -> client.putJson(apiPath("some_action_group"), allowedActionsArray("a", "b", "c"))),
            "allowed_actions"
        );

        final ToXContentObject unknownJsonFields = (builder, params) -> {
            builder.startObject().field("a", "b").field("c", "d").field("allowed_actions");
            allowedActionsArray("g", "h").toXContent(builder, params);
            return builder.endObject();
        };
        assertInvalidKeys(badRequest(() -> client.putJson(apiPath("some_action_group"), unknownJsonFields)), "a,c");

        assertNullValuesInArray(badRequest(() -> client.putJson(apiPath("some_action_group"), (builder, params) -> {
            builder.startObject().field("type", randomType()).field("allowed_actions");
            allowedActionsArray("g", null, "f").toXContent(builder, params);
            return builder.endObject();
        })));
        // patch
        badRequest(() -> client.patch(apiPath("some_action_group"), EMPTY_BODY));
        badRequest(() -> client.patch(apiPath(), patch(addOp("some_action_group", EMPTY_BODY))));
        badRequest(() -> client.patch(apiPath(), patch(replaceOp("some_action_group", EMPTY_BODY))));

        badRequestWithMessage(
            () -> client.patch(apiPath(), patch(addOp("kibana_user", actionGroup("a")))),
            "kibana_user is an existing role. A action group cannot be named with an existing role name."
        );
        badRequestWithMessage(
            () -> client.patch(apiPath(), patch(addOp("reference_itself", actionGroup("reference_itself")))),
            "reference_itself cannot be an allowed_action of itself"
        );

        assertMissingMandatoryKeys(
            badRequest(() -> client.patch(apiPath(), patch(addOp("some_action_group", allowedActionsArray("a", "b", "c"))))),
            "allowed_actions"
        );
        badRequest(() -> client.patch(apiPath(), patch(addOp("some_action_group", (ToXContentObject) (builder, params) -> {
            builder.startObject().field("type", "aaaa").field("allowed_actions");
            allowedActionsArray("g", "f").toXContent(builder, params);
            return builder.endObject();
        }))));

        badRequest(() -> client.patch(apiPath(), patch(addOp("some_action_group", (ToXContentObject) (builder, parameter) -> {
            builder.startObject();
            unknownJsonFields.toXContent(builder, parameter);
            return builder.endObject();
        }))));
        assertNullValuesInArray(
            badRequest(() -> client.patch(apiPath(), patch(addOp("some_action_group", (ToXContentObject) (builder, params) -> {
                builder.startObject().field("type", randomType()).field("allowed_actions");
                allowedActionsArray("g", null, "f").toXContent(builder, params);
                return builder.endObject();
            }))))
        );
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
