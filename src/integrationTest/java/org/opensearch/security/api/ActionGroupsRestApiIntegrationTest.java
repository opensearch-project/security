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

    /** Stored without REST validation, as on a cluster that saved an unknown action before it was rejected. */
    private final static String UNKNOWN_ACTION_GROUP = "unknown-action-group";

    private final static String UNKNOWN_ACTION = "cluster:admin/opensearch/nonexistent_permission";

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
            ),
            new TestSecurityConfig.ActionGroup(UNKNOWN_ACTION_GROUP, TestSecurityConfig.ActionGroup.Type.CLUSTER, UNKNOWN_ACTION)
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
                return actionGroup(hidden, reserved, _static, "cluster:monitor/health", "cluster:monitor/state");
            }

            @Override
            public ToXContentObject jsonPropertyPayload() {
                return configJsonArray("cluster:monitor/health", "cluster:monitor/state", "indices:data/read/search");
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
            assertThat(client.putJson(apiPath(), actionGroups(Map.of("some_group", actionGroup("cluster:monitor/health")))), isForbidden());
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
    public void rejectsUnknownAllowedActionsBeforeSaving() throws Exception {
        final String name = "allowed-actions-validation";
        final String batch = name + "-batch";
        final String referrer = name + "-referrer";
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            try {
                // put
                assertThat(
                    client.putJson(apiPath(name), actionGroup(UNKNOWN_ACTION, "missing_nested_group")),
                    isBadRequest().withAttribute("/reason", "Unknown or invalid action group permissions")
                        .withAttribute("/invalid_permissions/0", "/" + name + "/allowed_actions/0: \"" + UNKNOWN_ACTION + "\"")
                        .withAttribute("/invalid_permissions/1", "/" + name + "/allowed_actions/1: \"missing_nested_group\"")
                );
                assertThat(client.get(apiPath(name)), isNotFound());
                assertThat(client.putJson(apiPath(name), actionGroup("/[/")), isBadRequest());
                assertThat(client.get(apiPath(name)), isNotFound());
                // registered actions, static and dynamic action groups and patterns are accepted
                assertThat(
                    client.putJson(
                        apiPath(name),
                        actionGroup(
                            "cluster:monitor/health",
                            "cluster_monitor",
                            UNKNOWN_ACTION_GROUP,
                            "cluster:admin/opensearch/future/*",
                            "/indices:.*/"
                        )
                    ),
                    isCreated()
                );
                final var original = client.get(apiPath(name)).getBody();
                assertThat(client.putJson(apiPath(name), actionGroup(UNKNOWN_ACTION)), isBadRequest());

                // patch
                assertThat(
                    client.patch(apiPath(name), patch(replaceOp("allowed_actions", configJsonArray(UNKNOWN_ACTION)))),
                    isBadRequest()
                );
                assertThat(client.patch(apiPath(), patch(replaceOp(name, actionGroup(UNKNOWN_ACTION)))), isBadRequest());
                // one invalid entry rejects the whole batch: nothing is saved
                assertThat(
                    client.patch(
                        apiPath(),
                        patch(addOp(batch, actionGroup("cluster:monitor/health")), replaceOp(name, actionGroup(UNKNOWN_ACTION)))
                    ),
                    isBadRequest("/invalid_permissions/0", "/" + name + "/allowed_actions/0: \"" + UNKNOWN_ACTION + "\"")
                );
                assertThat(client.get(apiPath(batch)), isNotFound());
                assertThat(client.get(apiPath(name)).getBody(), is(original));
                // a group may reference a group created in the same batch
                assertThat(
                    client.patch(
                        apiPath(),
                        patch(addOp(referrer, actionGroup(batch)), addOp(batch, actionGroup("cluster:monitor/health")))
                    ),
                    isOk()
                );
                assertActionGroup(ok(() -> client.get(apiPath(referrer))), referrer, List.of(batch));
                // self-reference keeps its own message
                assertThat(
                    client.patch(apiPath(), patch(addOp("reference_itself", actionGroup("reference_itself")))),
                    isBadRequest("/message", "reference_itself cannot be an allowed_action of itself")
                );
                // a previously stored unknown action does not block changes to other groups
                assertThat(client.patch(apiPath(), patch(replaceOp(name, actionGroup("cluster:monitor/state")))), isOk());
                assertActionGroup(ok(() -> client.get(apiPath(name))), name, List.of("cluster:monitor/state"));
            } finally {
                client.delete(apiPath(referrer));
                client.delete(apiPath(batch));
                client.delete(apiPath(name));
            }
        }
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
            assertThat(
                client.putJson(
                    apiPath(),
                    actionGroups(
                        Map.of(
                            first,
                            actionGroup("cluster:monitor/health", "cluster:monitor/state"),
                            second,
                            actionGroup("indices:data/read/search")
                        )
                    )
                ),
                isOk()
            );
            assertActionGroup(ok(() -> client.get(apiPath(first))), first, List.of("cluster:monitor/health", "cluster:monitor/state"));
            assertActionGroup(ok(() -> client.get(apiPath(second))), second, List.of("indices:data/read/search"));

            // update one, create another; the omitted group is untouched
            assertThat(
                client.putJson(
                    apiPath(),
                    actionGroups(
                        Map.of(
                            first,
                            actionGroup("cluster:monitor/health", "cluster:monitor/state", "cluster:monitor/nodes/info"),
                            third,
                            actionGroup("indices:data/read/get")
                        )
                    )
                ),
                isOk()
            );
            assertActionGroup(
                ok(() -> client.get(apiPath(first))),
                first,
                List.of("cluster:monitor/health", "cluster:monitor/state", "cluster:monitor/nodes/info")
            );
            assertActionGroup(ok(() -> client.get(apiPath(second))), second, List.of("indices:data/read/search"));
            assertActionGroup(ok(() -> client.get(apiPath(third))), third, List.of("indices:data/read/get"));

            // one entry named after an existing role rejects the whole request: the valid entry is not written
            assertThat(
                client.putJson(
                    apiPath(),
                    actionGroups(
                        Map.of(rejected, actionGroup("indices:data/write/index"), "kibana_user", actionGroup("indices:data/write/delete"))
                    )
                ),
                isBadRequest("/message", "kibana_user is an existing role. A action group cannot be named with an existing role name.")
            );
            assertThat(client.get(apiPath(rejected)), isNotFound());

            // one self-referencing entry rejects the whole request
            assertThat(
                client.putJson(
                    apiPath(),
                    actionGroups(Map.of(rejected, actionGroup("indices:data/write/index"), "self_ref", actionGroup("self_ref")))
                ),
                isBadRequest("/message", "self_ref cannot be an allowed_action of itself")
            );
            assertThat(client.get(apiPath(rejected)), isNotFound());

            // one entry with an invalid type rejects the whole request
            final ToXContentObject invalidType = (builder, params) -> {
                builder.startObject().field("type", "asdasdsad").field("allowed_actions");
                configJsonArray("indices:data/read/mget").toXContent(builder, params);
                return builder.endObject();
            };
            assertThat(
                client.putJson(apiPath(), actionGroups(Map.of(rejected, actionGroup("indices:data/write/index"), "bad_type", invalidType))),
                isBadRequest("/message", "Invalid action group type: asdasdsad. Supported types are: cluster, index.")
            );
            assertThat(client.get(apiPath(rejected)), isNotFound());

            // groups may reference other groups in the same request, in either order. References are checked against the
            // configuration that would be saved, so the result cannot depend on entry order.
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

            // a reference to a group that exists neither in the request nor in the configuration rejects the whole request
            assertThat(
                client.putJson(
                    apiPath(),
                    actionGroups(Map.of(rejected, actionGroup("indices:data/write/index"), third, actionGroup("does_not_exist_group")))
                ),
                isBadRequest("/invalid_permissions/0", "/" + third + "/allowed_actions/0: \"does_not_exist_group\"")
            );
            assertThat(client.get(apiPath(rejected)), isNotFound());
            assertActionGroup(ok(() -> client.get(apiPath(third))), third, List.of("indices:data/read/get"));

            // more entries than the configured cap
            final Map<String, ToXContentObject> tooMany = Map.of(
                first,
                actionGroup("cluster:monitor/health"),
                second,
                actionGroup("cluster:monitor/state"),
                third,
                actionGroup("indices:data/read/search"),
                rejected,
                actionGroup("indices:data/read/get")
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
            client.putJson(
                apiPath(),
                actionGroups(Map.of(REST_ADMIN_PERMISSION_ACTION_GROUP, actionGroup("cluster:monitor/health", "cluster:monitor/state")))
            ),
            isForbidden()
        );
        assertThat(
            client.patch(
                apiPath(),
                patch(replaceOp(REST_ADMIN_PERMISSION_ACTION_GROUP, actionGroup("cluster:monitor/health", "cluster:monitor/state")))
            ),
            isForbidden()
        );
        assertThat(
            client.patch(
                apiPath(REST_ADMIN_PERMISSION_ACTION_GROUP),
                patch(replaceOp("allowed_actions", configJsonArray("indices:data/read/search", "indices:data/read/get")))
            ),
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
        assertThat(client.putJson(apiPath(tempGroup), actionGroup("cluster:monitor/health", "cluster:monitor/state")), isOk());
        assertThat(
            client.patch(apiPath(), patch(replaceOp(tempGroup, actionGroup("cluster:monitor/health", "cluster:monitor/state")))),
            isOk()
        );
        assertThat(
            client.patch(
                apiPath(tempGroup),
                patch(replaceOp("allowed_actions", configJsonArray("indices:data/read/search", "indices:data/read/get")))
            ),
            isOk()
        );
        assertThat(client.delete(apiPath(tempGroup)), isOk());
    }

    @Override
    void verifyCrudOperations(final Boolean hidden, final Boolean reserved, final TestRestClient client) throws Exception {
        // create
        assertThat(
            client.putJson(apiPath("new_action_group"), actionGroup(hidden, reserved, "cluster:monitor/health", "cluster:monitor/state")),
            isCreated()
        );
        var response = client.get(apiPath("new_action_group"));
        assertThat(response, isOk());
        assertActionGroup(response, "new_action_group", List.of("cluster:monitor/health", "cluster:monitor/state"));

        // update
        assertThat(
            client.putJson(apiPath("new_action_group"), actionGroup(hidden, reserved, "indices:data/read/search", "indices:data/read/get")),
            isOk()
        );
        response = client.get(apiPath("new_action_group"));
        assertThat(response, isOk());
        assertActionGroup(response, "new_action_group", List.of("indices:data/read/search", "indices:data/read/get"));

        // delete
        assertThat(client.delete(apiPath("new_action_group")), isOk());
        response = client.get(apiPath("new_action_group"));
        assertThat(response, isNotFound());

        // patch add
        assertThat(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        "new_action_group_for_patch",
                        actionGroup(hidden, reserved, "indices:data/write/index", "indices:data/write/delete")
                    )
                )
            ),
            isOk()
        );
        response = client.get(apiPath("new_action_group_for_patch"));
        assertThat(response, isOk());
        assertActionGroup(response, "new_action_group_for_patch", List.of("indices:data/write/index", "indices:data/write/delete"));

        // patch replace
        assertThat(
            client.patch(
                apiPath("new_action_group_for_patch"),
                patch(replaceOp("allowed_actions", configJsonArray("indices:data/read/mget", "indices:monitor/stats")))
            ),
            isOk()
        );
        response = client.get(apiPath("new_action_group_for_patch"));
        assertThat(response, isOk());
        assertActionGroup(response, "new_action_group_for_patch", List.of("indices:data/read/mget", "indices:monitor/stats"));

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
        assertThat(client.putJson(apiPath(), actionGroups(Map.of("", actionGroup("cluster:monitor/health")))), isBadRequest());
        assertThat(client.putJson(apiPath("some_action_group"), EMPTY_BODY), isBadRequest());
        assertThat(
            client.putJson(apiPath("kibana_user"), actionGroup("cluster:monitor/health", "cluster:monitor/state")),
            isBadRequest("/message", "kibana_user is an existing role. A action group cannot be named with an existing role name.")
        );
        assertThat(
            client.putJson(apiPath("reference_itself"), actionGroup("reference_itself")),
            isBadRequest("/message", "reference_itself cannot be an allowed_action of itself")
        );
        assertThat(client.putJson(apiPath("some_action_group"), (builder, params) -> {
            builder.startObject().field("type", "asdasdsad").field("allowed_actions");
            configJsonArray("indices:data/read/mget", "indices:data/write/delete").toXContent(builder, params);
            return builder.endObject();
        }), isBadRequest("/message", "Invalid action group type: asdasdsad. Supported types are: cluster, index."));

        assertThat(
            client.putJson(
                apiPath("some_action_group"),
                configJsonArray("cluster:monitor/health", "cluster:monitor/state", "indices:data/read/search")
            ),
            isBadRequest("/missing_mandatory_keys/keys", "allowed_actions")
        );

        // duplicate check retained from original
        assertThat(
            client.putJson(
                apiPath("some_action_group"),
                configJsonArray("cluster:monitor/health", "cluster:monitor/state", "indices:data/read/search")
            ),
            isBadRequest("/missing_mandatory_keys/keys", "allowed_actions")
        );

        final ToXContentObject unknownJsonFields = (builder, params) -> {
            builder.startObject().field("a", "b").field("c", "d").field("allowed_actions");
            configJsonArray("indices:data/read/mget", "indices:monitor/stats").toXContent(builder, params);
            return builder.endObject();
        };
        assertThat(client.putJson(apiPath("some_action_group"), unknownJsonFields), isBadRequest("/invalid_keys/keys", "a,c"));

        assertThat(client.putJson(apiPath("some_action_group"), (builder, params) -> {
            builder.startObject().field("type", TestSecurityConfig.ActionGroup.Type.CLUSTER.type()).field("allowed_actions");
            configJsonArray("indices:data/read/mget", null, "indices:data/write/delete").toXContent(builder, params);
            return builder.endObject();
        }), isBadRequest("/reason", "`null` or blank values are not allowed as json array elements"));

        // patch
        assertThat(client.patch(apiPath("some_action_group"), EMPTY_BODY), isBadRequest());
        assertThat(client.patch(apiPath(), patch(addOp("some_action_group", EMPTY_BODY))), isBadRequest());
        assertThat(client.patch(apiPath(), patch(replaceOp("some_action_group", EMPTY_BODY))), isBadRequest());
        assertThat(
            client.patch(apiPath(), patch(addOp("kibana_user", actionGroup("cluster:monitor/health")))),
            isBadRequest("/message", "kibana_user is an existing role. A action group cannot be named with an existing role name.")
        );
        assertThat(
            client.patch(apiPath(), patch(addOp("reference_itself", actionGroup("reference_itself")))),
            isBadRequest("/message", "reference_itself cannot be an allowed_action of itself")
        );
        assertThat(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        "some_action_group",
                        configJsonArray("cluster:monitor/health", "cluster:monitor/state", "indices:data/read/search")
                    )
                )
            ),
            isBadRequest("/missing_mandatory_keys/keys", "allowed_actions")
        );

        assertThat(client.patch(apiPath(), patch(addOp("some_action_group", (ToXContentObject) (builder, params) -> {
            builder.startObject().field("type", "aaaa").field("allowed_actions");
            configJsonArray("indices:data/read/mget", "indices:data/write/delete").toXContent(builder, params);
            return builder.endObject();
        }))), isBadRequest());

        assertThat(client.patch(apiPath(), patch(addOp("some_action_group", (ToXContentObject) (builder, parameter) -> {
            builder.startObject();
            unknownJsonFields.toXContent(builder, parameter);
            return builder.endObject();
        }))), isBadRequest());

        assertThat(client.patch(apiPath(), patch(addOp("some_action_group", (ToXContentObject) (builder, params) -> {
            builder.startObject().field("type", TestSecurityConfig.ActionGroup.Type.CLUSTER.type()).field("allowed_actions");
            configJsonArray("indices:data/read/mget", null, "indices:data/write/delete").toXContent(builder, params);
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
