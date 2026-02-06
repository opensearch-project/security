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

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.removeOp;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class RolesRestApiIntegrationTest extends AbstractConfigEntityApiIntegrationTest {

    private final static String REST_API_ADMIN_ACTION_ROLES_ONLY = "rest_api_admin_action_roles_only";

    private final static String REST_ADMIN_PERMISSION_ROLE = "rest-admin-permission-role";

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().users(
        new TestSecurityConfig.User(REST_API_ADMIN_ACTION_ROLES_ONLY).roles(
            new TestSecurityConfig.Role("rest_admin_role").clusterPermissions(restAdminPermission(Endpoint.ROLES))
        )
    ).roles(new TestSecurityConfig.Role(REST_ADMIN_PERMISSION_ROLE).clusterPermissions(allRestAdminPermissions())).build();

    public RolesRestApiIntegrationTest() {
        super("roles", new TestDescriptor() {
            @Override
            public String entityJsonProperty() {
                return "cluster_permissions";
            }

            @Override
            public ToXContentObject entityPayload(Boolean hidden, Boolean reserved, Boolean _static) {
                return roleWithClusterPermissions(hidden, reserved, _static, "a", "b");
            }

            @Override
            public ToXContentObject jsonPropertyPayload() {
                return configJsonArray();
            }

            @Override
            public Optional<String> restAdminLimitedUser() {
                return Optional.of(REST_API_ADMIN_ACTION_ROLES_ONLY);
            }
        });
    }

    @Test
    public void forbiddenForRegularUsers() throws Exception {
        super.forbiddenForRegularUsers(localCluster);
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

    @Override
    void verifyCrudOperations(final Boolean hidden, final Boolean reserved, final TestRestClient client) throws Exception {
        for (ToXContentObject clusterPermissions : clusterPermissionsOptions(false)) {
            for (ToXContentObject indexPermissions : indexPermissionsOptions(false)) {
                for (ToXContentObject tenantPermissions : tenantPermissionsOptions(false)) {
                    verifyCrudOperationsForCombination(hidden, reserved, client, clusterPermissions, indexPermissions, tenantPermissions);
                }
            }
        }
    }

    void verifyCrudOperationsForCombination(
        final Boolean hidden,
        final Boolean reserved,
        final TestRestClient client,
        ToXContentObject clusterPermissions,
        ToXContentObject indexPermissions,
        ToXContentObject tenantPermissions
    ) throws Exception {
        final var newRoleJson = Strings.toString(
            XContentType.JSON,
            role(hidden, reserved, clusterPermissions, indexPermissions, tenantPermissions)
        );
        assertThat(client.putJson(apiPath("new_role"), newRoleJson), isCreated());
        assertRole(ok(() -> client.get(apiPath("new_role"))), "new_role", hidden, reserved, newRoleJson);

        final var updatedRoleJson = Strings.toString(
            XContentType.JSON,
            role(hidden, reserved, clusterPermissions, indexPermissions, tenantPermissions)
        );
        assertThat(client.putJson(apiPath("new_role"), updatedRoleJson), isOk());
        assertRole(ok(() -> client.get(apiPath("new_role"))), "new_role", hidden, reserved, updatedRoleJson);

        assertThat(client.delete(apiPath("new_role")), isOk());
        assertThat(client.get(apiPath("new_role")), isNotFound());

        final var roleForPatch = role(hidden, reserved, configJsonArray("a", "b"), configJsonArray(), configJsonArray());
        assertThat(client.patch(apiPath(), patch(addOp("new_role_for_patch", roleForPatch))), isOk());
        assertRole(
            ok(() -> client.get(apiPath("new_role_for_patch"))),
            "new_role_for_patch",
            hidden,
            reserved,
            Strings.toString(XContentType.JSON, roleForPatch)
        );

        // TODO related to issue #4426
        assertThat(client.patch(apiPath("new_role_for_patch"), patch(replaceOp("cluster_permissions", configJsonArray("a", "b")))), isOk());
        assertThat(
            client.patch(apiPath("new_role_for_patch"), patch(replaceOp("cluster_permissions", configJsonArray("a", "b", "c")))),
            isOk()
        );
        assertThat(client.patch(apiPath("new_role_for_patch"), patch(addOp("index_permissions", indexPermissions))), isOk());
        assertThat(client.patch(apiPath("new_role_for_patch"), patch(addOp("tenant_permissions", tenantPermissions))), isOk());
        assertThat(client.patch(apiPath(), patch(removeOp("new_role_for_patch"))), isOk());
        assertThat(client.get(apiPath("new_role_for_patch")), isNotFound());
    }

    @Override
    void verifyBadRequestOperations(TestRestClient client) throws Exception {
        // put
        assertThat(client.putJson(apiPath(randomAlphanumericString()), EMPTY_BODY), isBadRequest());
        assertThat(client.putJson(apiPath(randomAlphanumericString()), (builder, params) -> {
            builder.startObject();
            builder.field("cluster_permissions");
            clusterPermissionsOptions(false).get(0).toXContent(builder, params);
            builder.field("cluster_permissions");
            clusterPermissionsOptions(false).get(0).toXContent(builder, params);
            return builder.endObject();
        }), isBadRequest());
        assertInvalidKeys(client.putJson(apiPath(randomAlphanumericString()), (builder, params) -> {
            builder.startObject();
            builder.field("unknown_json_property");
            configJsonArray("a", "b").toXContent(builder, params);
            builder.field("cluster_permissions");
            clusterPermissionsOptions(false).get(0).toXContent(builder, params);
            return builder.endObject();
        }), "unknown_json_property");
        assertWrongDataType(client.putJson(apiPath(randomAlphanumericString()), (builder, params) -> {
            builder.startObject();
            builder.field("cluster_permissions").value("a");
            builder.field("index_permissions").value("b");
            return builder.endObject();
        }), Map.of("cluster_permissions", "Array expected", "index_permissions", "Array expected"));
        assertNullValuesInArray(
            client.putJson(
                apiPath(randomAlphanumericString()),
                role(clusterPermissionsOptions(true).get(0), indexPermissionsOptions(true).get(0), tenantPermissionsOptions(true).get(0))
            )
        );
        // patch
        final var predefinedRoleName = randomAlphanumericString();
        assertThat(
            client.putJson(apiPath(predefinedRoleName), role(configJsonArray("a", "b"), configJsonArray(), configJsonArray())),
            isCreated()
        );

        assertThat(client.patch(apiPath(), patch(addOp("some_new_role", EMPTY_BODY))), isBadRequest());
        for (String field : List.of("cluster_permissions", "index_permissions", "tenant_permissions")) {
            assertThat(client.patch(apiPath(predefinedRoleName), patch(replaceOp(field, EMPTY_BODY))), isBadRequest());
        }

        assertThat(
            client.patch(
                apiPath(randomAlphanumericString()),
                patch(addOp(randomAlphanumericString(), (ToXContentObject) (builder, params) -> {
                    builder.startObject();
                    builder.field("cluster_permissions");
                    clusterPermissionsOptions(false).get(0).toXContent(builder, params);
                    builder.field("cluster_permissions");
                    clusterPermissionsOptions(false).get(0).toXContent(builder, params);
                    return builder.endObject();
                }))
            ),
            isBadRequest()
        );

        assertThat(client.patch(apiPath(randomAlphanumericString()), (builder, params) -> {
            builder.startObject();
            builder.field("unknown_json_property");
            configJsonArray("a", "b").toXContent(builder, params);
            builder.field("cluster_permissions");
            clusterPermissionsOptions(false).get(0).toXContent(builder, params);
            return builder.endObject();
        }), isBadRequest());

        var response = client.patch(apiPath(), patch(addOp(randomAlphanumericString(), (ToXContentObject) (builder, params) -> {
            builder.startObject();
            builder.field("cluster_permissions").value("a");
            builder.field("index_permissions").value("b");
            return builder.endObject();
        })));
        assertThat(
            response,
            isBadRequest().withAttribute("/status", "error")
                .withAttribute("/cluster_permissions", "Array expected")
                .withAttribute("/index_permissions", "Array expected")
        );

        response = badRequest(() -> client.patch(apiPath(predefinedRoleName), patch(replaceOp("cluster_permissions", "true"))));
        assertThat(response, isBadRequest().withAttribute("/status", "error").withAttribute("/cluster_permissions", "Array expected"));
        assertNullValuesInArray(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        randomAlphanumericString(),
                        role(
                            clusterPermissionsOptions(true).get(0),
                            indexPermissionsOptions(true).get(0),
                            tenantPermissionsOptions(true).get(0)
                        )
                    )
                )
            )
        );
        // TODO related to issue #4426
        assertNullValuesInArray(
            client.patch(apiPath(predefinedRoleName), patch(replaceOp("cluster_permissions", clusterPermissionsOptions(true).get(0))))
        );
    }

    @Override
    void forbiddenToCreateEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {
        assertThat(client.putJson(apiPath("new_rest_admin_role"), roleWithClusterPermissions(randomRestAdminPermission())), isForbidden());
        assertThat(
            client.patch(apiPath(), patch(addOp("new_rest_admin_action_group", roleWithClusterPermissions(randomRestAdminPermission())))),
            isForbidden()
        );
    }

    @Override
    void forbiddenToUpdateAndDeleteExistingEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {
        // update
        assertThat(
            client.putJson(
                apiPath(REST_ADMIN_PERMISSION_ROLE),
                role(clusterPermissionsOptions(false).get(0), indexPermissionsOptions(false).get(0), tenantPermissionsOptions(false).get(0))
            ),
            isForbidden()
        );
        assertThat(
            client.patch(
                apiPath(),
                patch(
                    replaceOp(
                        REST_ADMIN_PERMISSION_ROLE,
                        role(
                            clusterPermissionsOptions(false).get(0),
                            indexPermissionsOptions(false).get(0),
                            tenantPermissionsOptions(false).get(0)
                        )
                    )
                )
            ),
            isForbidden()
        );
        assertThat(
            client.patch(
                apiPath(REST_ADMIN_PERMISSION_ROLE),
                patch(replaceOp("cluster_permissions", clusterPermissionsOptions(false).get(0)))
            ),
            isForbidden()
        );
        // remove
        assertThat(client.patch(apiPath(), patch(removeOp(REST_ADMIN_PERMISSION_ROLE))), isForbidden());
        assertThat(client.patch(apiPath(REST_ADMIN_PERMISSION_ROLE), patch(removeOp("cluster_permissions"))), isForbidden());
        assertThat(client.delete(apiPath(REST_ADMIN_PERMISSION_ROLE)), isForbidden());
    }

    void assertRole(
        final TestRestClient.HttpResponse response,
        final String roleName,
        final Boolean hidden,
        final Boolean reserved,
        final String expectedRoleJson
    ) throws IOException {
        final var expectedObjectNode = DefaultObjectMapper.readTree(expectedRoleJson);
        final var actualObjectNode = response.bodyAsJsonNode().get(roleName);
        final var expectedHidden = hidden != null && hidden;
        final var expectedReserved = reserved != null && reserved;
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("hidden").asBoolean(), is(expectedHidden));
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("reserved").asBoolean(), is(expectedReserved));
        assertThat(actualObjectNode.toPrettyString(), not(actualObjectNode.get("static").asBoolean()));
        assertThat(
            actualObjectNode.toPrettyString(),
            actualObjectNode.get("cluster_permissions"),
            is(expectedObjectNode.get("cluster_permissions"))
        );
        // TODO related to issue #4426
        for (Iterator<JsonNode> it = expectedObjectNode.get("index_permissions").elements(); it.hasNext();) {
            final var indexPermission = (ObjectNode) it.next();
            if (indexPermission.has("dls") && indexPermission.get("dls").isNull()) {
                indexPermission.remove("dls");
            }
            if (indexPermission.has("fls") && indexPermission.get("fls").isNull()) {
                indexPermission.set("fls", DefaultObjectMapper.objectMapper.createArrayNode());
            }
            if (indexPermission.has("masked_fields") && indexPermission.get("masked_fields").isNull()) {
                indexPermission.set("masked_fields", DefaultObjectMapper.objectMapper.createArrayNode());
            }
        }

        assertThat(
            actualObjectNode.toPrettyString(),
            actualObjectNode.get("index_permissions"),
            is(expectedObjectNode.get("index_permissions"))
        );
        assertThat(
            actualObjectNode.toPrettyString(),
            actualObjectNode.get("tenant_permissions"),
            is(expectedObjectNode.get("tenant_permissions"))
        );
    }

    static ToXContentObject roleWithClusterPermissions(final String... clusterPermissions) {
        return roleWithClusterPermissions(null, null, null, clusterPermissions);
    }

    static ToXContentObject roleWithClusterPermissions(
        final Boolean hidden,
        final Boolean reserved,
        final Boolean _static,
        final String... clusterPermissions
    ) {
        return role(
            hidden,
            reserved,
            _static,
            (builder, params) -> configJsonArray(clusterPermissions).toXContent(builder, params),
            null,
            null
        );
    }

    static ToXContentObject role(
        final ToXContentObject clusterPermissions,
        final ToXContentObject indexPermissions,
        final ToXContentObject tenantPermissions
    ) {
        return role(null, null, null, clusterPermissions, indexPermissions, tenantPermissions);
    }

    static ToXContentObject role(
        final Boolean hidden,
        final Boolean reserved,
        final ToXContentObject clusterPermissions,
        final ToXContentObject indexPermissions,
        final ToXContentObject tenantPermissions
    ) {
        return role(hidden, reserved, null, clusterPermissions, indexPermissions, tenantPermissions);
    }

    static ToXContentObject role(
        final Boolean hidden,
        final Boolean reserved,
        final Boolean _static,
        final ToXContentObject clusterPermissions,
        final ToXContentObject indexPermissions,
        final ToXContentObject tenantPermissions
    ) {
        return (builder, params) -> {
            builder.startObject();
            builder.field("cluster_permissions");
            if (clusterPermissions != null) {
                clusterPermissions.toXContent(builder, params);
            } else {
                builder.startArray().endArray();
            }
            builder.field("index_permissions");
            if (indexPermissions != null) {
                indexPermissions.toXContent(builder, params);
            } else {
                builder.startArray().endArray();
            }
            builder.field("tenant_permissions");
            if (tenantPermissions != null) {
                tenantPermissions.toXContent(builder, params);
            } else {
                builder.startArray().endArray();
            }
            if (hidden != null) {
                builder.field("hidden", hidden);
            }
            if (reserved != null) {
                builder.field("reserved", reserved);
            }
            if (_static != null) {
                builder.field("static", _static);
            }
            return builder.endObject();
        };
    }

    List<ToXContentObject> clusterPermissionsOptions(final boolean useNulls) {
        return useNulls
            ? List.of(configJsonArray(generateArrayValues(useNulls)))
            : List.of(configJsonArray(generateArrayValues(false)), configJsonArray());
    }

    List<ToXContentObject> indexPermissionsOptions(final boolean useNulls) {
        if (useNulls) {
            return List.of((builder, params) -> {
                builder.startArray();
                randomIndexPermission(useNulls).toXContent(builder, params);
                return builder.endArray();
            });
        } else {
            return List.of((builder, params) -> {
                builder.startArray();
                randomIndexPermission(false).toXContent(builder, params);
                return builder.endArray();
            }, (builder, params) -> {
                builder.startArray();
                builder.endArray();
                return builder;
            });
        }
    }

    ToXContentObject randomIndexPermission(final boolean useNulls) {
        return (builder, params) -> {
            builder.startObject();

            builder.field("index_patterns");
            indexPatternsOptions(useNulls).get(0).toXContent(builder, params);

            builder.field("dls");
            dlsOptions().get(0).toXContent(builder, params);

            builder.field("fls");
            flsOptions(useNulls).get(0).toXContent(builder, params);

            builder.field("masked_fields");
            maskedFieldsOptions(useNulls).get(0).toXContent(builder, params);

            builder.field("allowed_actions");
            allowedActionsOptions(useNulls).get(0).toXContent(builder, params);

            return builder.endObject();
        };
    }

    List<ToXContentObject> indexPatternsOptions(final boolean useNulls) {
        return useNulls
            ? List.of(configJsonArray(generateArrayValues(useNulls)))
            : List.of(configJsonArray(generateArrayValues(false)), configJsonArray());
    }

    List<ToXContentObject> tenantPermissionsOptions(final boolean useNulls) {
        if (useNulls) {
            return List.of((builder, params) -> {
                builder.startArray();
                tenantPermission(useNulls).toXContent(builder, params);
                return builder.endArray();
            });
        } else {
            return List.of((builder, params) -> {
                builder.startArray();
                tenantPermission(false).toXContent(builder, params);
                return builder.endArray();
            }, (builder, params) -> {
                builder.startArray();
                builder.endArray();
                return builder;
            });
        }
    }

    ToXContentObject tenantPermission(final boolean useNulls) {
        return (builder, params) -> {
            builder.startObject().field("tenant_patterns");
            List<ToXContentObject> patterns = useNulls
                ? List.of(configJsonArray(generateArrayValues(useNulls)))
                : List.of(configJsonArray(generateArrayValues(false)), configJsonArray());
            patterns.get(0).toXContent(builder, params);
            builder.field("allowed_actions");
            allowedActionsOptions(useNulls).get(0).toXContent(builder, params);
            return builder.endObject();
        };
    }

    List<ToXContentObject> dlsOptions() {
        return List.of((builder, params) -> builder.value("str1234567"), (builder, params) -> builder.nullValue());
    }

    List<ToXContentObject> flsOptions(final boolean useNullValues) {
        return useNullValues
            ? List.of(configJsonArray(generateArrayValues(useNullValues)))
            : List.of(configJsonArray(generateArrayValues(false)), configJsonArray(), (builder, params) -> builder.nullValue());
    }

    List<ToXContentObject> maskedFieldsOptions(final boolean useNullValues) {
        return useNullValues
            ? List.of(configJsonArray(generateArrayValues(useNullValues)))
            : List.of(configJsonArray(generateArrayValues(false)), configJsonArray(), (builder, params) -> builder.nullValue());
    }

    List<ToXContentObject> allowedActionsOptions(final boolean useNullValues) {
        return useNullValues
            ? List.of(configJsonArray(generateArrayValues(useNullValues)))
            : List.of(configJsonArray(generateArrayValues(false)), configJsonArray());
    }
}
