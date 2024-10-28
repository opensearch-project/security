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

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.removeOp;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;

public class RolesRestApiIntegrationTest extends AbstractConfigEntityApiIntegrationTest {

    private final static String REST_API_ADMIN_ACTION_ROLES_ONLY = "rest_api_admin_action_roles_only";

    private final static String REST_ADMIN_PERMISSION_ROLE = "rest-admin-permission-role";

    static {
        testSecurityConfig.withRestAdminUser(REST_API_ADMIN_ACTION_ROLES_ONLY, restAdminPermission(Endpoint.ROLES))
            .roles(new TestSecurityConfig.Role(REST_ADMIN_PERMISSION_ROLE).clusterPermissions(allRestAdminPermissions()));
    }

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
                return randomFrom(List.of(configJsonArray(generateArrayValues(false)), configJsonArray()));
            }

            @Override
            public Optional<String> restAdminLimitedUser() {
                return Optional.of(REST_API_ADMIN_ACTION_ROLES_ONLY);
            }
        });
    }

    @Override
    void verifyCrudOperations(final Boolean hidden, final Boolean reserved, final TestRestClient client) throws Exception {
        final var newRoleJson = Strings.toString(
            XContentType.JSON,
            role(hidden, reserved, randomClusterPermissions(false), randomIndexPermissions(false), randomTenantPermissions(false))
        );
        created(() -> client.putJson(apiPath("new_role"), newRoleJson));
        assertRole(ok(() -> client.get(apiPath("new_role"))), "new_role", hidden, reserved, newRoleJson);

        final var updatedRoleJson = Strings.toString(
            XContentType.JSON,
            role(hidden, reserved, randomClusterPermissions(false), randomIndexPermissions(false), randomTenantPermissions(false))
        );
        ok(() -> client.putJson(apiPath("new_role"), updatedRoleJson));
        assertRole(ok(() -> client.get(apiPath("new_role"))), "new_role", hidden, reserved, updatedRoleJson);

        ok(() -> client.delete(apiPath("new_role")));
        notFound(() -> client.get(apiPath("new_role")));

        final var roleForPatch = role(hidden, reserved, configJsonArray("a", "b"), configJsonArray(), configJsonArray());
        ok(() -> client.patch(apiPath(), patch(addOp("new_role_for_patch", roleForPatch))));
        assertRole(
            ok(() -> client.get(apiPath("new_role_for_patch"))),
            "new_role_for_patch",
            hidden,
            reserved,
            Strings.toString(XContentType.JSON, roleForPatch)
        );

        // TODO related to issue #4426
        ok(
            () -> client.patch(apiPath("new_role_for_patch"), patch(replaceOp("cluster_permissions", configJsonArray("a", "b")))),
            "No updates required"
        );
        ok(
            () -> client.patch(apiPath("new_role_for_patch"), patch(replaceOp("cluster_permissions", configJsonArray("a", "b", "c")))),
            "'new_role_for_patch' updated."
        );
        ok(() -> client.patch(apiPath("new_role_for_patch"), patch(addOp("index_permissions", randomIndexPermissions(false)))));
        ok(() -> client.patch(apiPath("new_role_for_patch"), patch(addOp("tenant_permissions", randomTenantPermissions(false)))));

        ok(() -> client.patch(apiPath(), patch(removeOp("new_role_for_patch"))));
        notFound(() -> client.get(apiPath("new_role_for_patch")));
    }

    @Override
    void verifyBadRequestOperations(TestRestClient client) throws Exception {
        // put
        badRequest(() -> client.putJson(apiPath(randomAsciiAlphanumOfLength(5)), EMPTY_BODY));
        badRequest(() -> client.putJson(apiPath(randomAsciiAlphanumOfLength(5)), (builder, params) -> {
            builder.startObject();
            builder.field("cluster_permissions");
            randomClusterPermissions(false).toXContent(builder, params);
            builder.field("cluster_permissions");
            randomClusterPermissions(false).toXContent(builder, params);
            return builder.endObject();
        }));
        assertInvalidKeys(badRequest(() -> client.putJson(apiPath(randomAsciiAlphanumOfLength(5)), (builder, params) -> {
            builder.startObject();
            builder.field("unknown_json_property");
            configJsonArray("a", "b").toXContent(builder, params);
            builder.field("cluster_permissions");
            randomClusterPermissions(false).toXContent(builder, params);
            return builder.endObject();
        })), "unknown_json_property");
        assertWrongDataType(badRequest(() -> client.putJson(apiPath(randomAsciiAlphanumOfLength(5)), (builder, params) -> {
            builder.startObject();
            builder.field("cluster_permissions").value("a");
            builder.field("index_permissions").value("b");
            return builder.endObject();
        })), Map.of("cluster_permissions", "Array expected", "index_permissions", "Array expected"));
        assertNullValuesInArray(
            client.putJson(
                apiPath(randomAsciiAlphanumOfLength(5)),
                role(randomClusterPermissions(true), randomIndexPermissions(true), randomTenantPermissions(true))
            )
        );
        // patch
        final var predefinedRoleName = randomAsciiAlphanumOfLength(4);
        created(() -> client.putJson(apiPath(predefinedRoleName), role(configJsonArray("a", "b"), configJsonArray(), configJsonArray())));

        badRequest(() -> client.patch(apiPath(), patch(addOp("some_new_role", EMPTY_BODY))));
        badRequest(
            () -> client.patch(
                apiPath(predefinedRoleName),
                patch(replaceOp(randomFrom(List.of("cluster_permissions", "index_permissions", "tenant_permissions")), EMPTY_BODY))
            )
        );

        badRequest(
            () -> client.patch(
                apiPath(randomAsciiAlphanumOfLength(5)),
                patch(addOp(randomAsciiAlphanumOfLength(5), (ToXContentObject) (builder, params) -> {
                    builder.startObject();
                    builder.field("cluster_permissions");
                    randomClusterPermissions(false).toXContent(builder, params);
                    builder.field("cluster_permissions");
                    randomClusterPermissions(false).toXContent(builder, params);
                    return builder.endObject();
                }))
            )
        );
        badRequest(() -> client.patch(apiPath(randomAsciiAlphanumOfLength(5)), (builder, params) -> {
            builder.startObject();
            builder.field("unknown_json_property");
            configJsonArray("a", "b").toXContent(builder, params);
            builder.field("cluster_permissions");
            randomClusterPermissions(false).toXContent(builder, params);
            return builder.endObject();
        }));
        assertWrongDataType(
            badRequest(() -> client.patch(apiPath(), patch(addOp(randomAsciiAlphanumOfLength(5), (ToXContentObject) (builder, params) -> {
                builder.startObject();
                builder.field("cluster_permissions").value("a");
                builder.field("index_permissions").value("b");
                return builder.endObject();
            })))),
            Map.of("cluster_permissions", "Array expected", "index_permissions", "Array expected")
        );
        assertWrongDataType(
            badRequest(() -> client.patch(apiPath(predefinedRoleName), patch(replaceOp("cluster_permissions", "true")))),
            Map.of("cluster_permissions", "Array expected")
        );
        assertNullValuesInArray(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        randomAsciiAlphanumOfLength(5),
                        role(randomClusterPermissions(true), randomIndexPermissions(true), randomTenantPermissions(true))
                    )
                )
            )
        );
        // TODO related to issue #4426
        assertNullValuesInArray(
            client.patch(apiPath(predefinedRoleName), patch(replaceOp("cluster_permissions", randomClusterPermissions(true))))
        );
    }

    @Override
    void forbiddenToCreateEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {
        forbidden(() -> client.putJson(apiPath("new_rest_admin_role"), roleWithClusterPermissions(randomRestAdminPermission())));
        forbidden(
            () -> client.patch(
                apiPath(),
                patch(addOp("new_rest_admin_action_group", roleWithClusterPermissions(randomRestAdminPermission())))
            )
        );
    }

    @Override
    void forbiddenToUpdateAndDeleteExistingEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {
        // update
        forbidden(
            () -> client.putJson(
                apiPath(REST_ADMIN_PERMISSION_ROLE),
                role(randomClusterPermissions(false), randomIndexPermissions(false), randomTenantPermissions(false))
            )
        );
        forbidden(
            () -> client.patch(
                apiPath(),
                patch(
                    replaceOp(
                        REST_ADMIN_PERMISSION_ROLE,
                        role(randomClusterPermissions(false), randomIndexPermissions(false), randomTenantPermissions(false))
                    )
                )
            )
        );
        forbidden(
            () -> client.patch(
                apiPath(REST_ADMIN_PERMISSION_ROLE),
                patch(replaceOp("cluster_permissions", randomClusterPermissions(false)))
            )
        );
        // remove
        forbidden(() -> client.patch(apiPath(), patch(removeOp(REST_ADMIN_PERMISSION_ROLE))));
        forbidden(() -> client.patch(apiPath(REST_ADMIN_PERMISSION_ROLE), patch(removeOp("cluster_permissions"))));
        forbidden(() -> client.delete(apiPath(REST_ADMIN_PERMISSION_ROLE)));
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

    ToXContentObject randomClusterPermissions(final boolean useNulls) {
        return useNulls
            ? configJsonArray(generateArrayValues(useNulls))
            : randomFrom(List.of(configJsonArray(generateArrayValues(false)), configJsonArray()));
    }

    ToXContentObject randomIndexPermissions(final boolean useNulls) {
        return (builder, params) -> {
            final var possibleJson = useNulls
                ? randomIndexPermission(useNulls)
                : randomFrom(List.of(randomIndexPermission(false), (b, p) -> b));
            builder.startArray();
            possibleJson.toXContent(builder, params);
            return builder.endArray();
        };
    }

    ToXContentObject randomIndexPermission(final boolean useNulls) {
        return (builder, params) -> {
            builder.startObject();

            builder.field("index_patterns");
            randomIndexPatterns(useNulls).toXContent(builder, params);

            builder.field("dls");
            randomDls().toXContent(builder, params);

            builder.field("fls");
            randomFls(useNulls).toXContent(builder, params);

            builder.field("masked_fields");
            randomMaskedFields(useNulls).toXContent(builder, params);

            builder.field("allowed_actions");
            randomAllowedActions(useNulls).toXContent(builder, params);

            return builder.endObject();
        };
    }

    ToXContentObject randomIndexPatterns(final boolean useNulls) {
        return useNulls
            ? configJsonArray(generateArrayValues(useNulls))
            : randomFrom(List.of(configJsonArray(generateArrayValues(false)), configJsonArray()));
    }

    ToXContentObject randomTenantPermissions(final boolean useNulls) {
        return (builder, params) -> {
            final var possibleJson = useNulls ? tenantPermission(useNulls) : randomFrom(List.of(tenantPermission(false), (b, p) -> b));
            builder.startArray();
            possibleJson.toXContent(builder, params);
            return builder.endArray();
        };
    }

    ToXContentObject tenantPermission(final boolean useNulls) {
        return (builder, params) -> {
            builder.startObject().field("tenant_patterns");
            randomFrom(List.of(configJsonArray(generateArrayValues(useNulls)), configJsonArray())).toXContent(builder, params);
            builder.field("allowed_actions");
            randomAllowedActions(useNulls).toXContent(builder, params);
            return builder.endObject();
        };
    }

    ToXContentObject randomDls() {
        return randomFrom(
            List.of((builder, params) -> builder.value(randomAsciiAlphanumOfLength(10)), (builder, params) -> builder.nullValue())
        );
    }

    ToXContentObject randomFls(final boolean useNullValues) {
        return useNullValues
            ? configJsonArray(generateArrayValues(useNullValues))
            : randomFrom(List.of(configJsonArray(generateArrayValues(false)), configJsonArray(), (builder, params) -> builder.nullValue()));
    }

    ToXContentObject randomMaskedFields(final boolean useNullValues) {
        return useNullValues
            ? configJsonArray(generateArrayValues(useNullValues))
            : randomFrom(List.of(configJsonArray(generateArrayValues(false)), configJsonArray(), (builder, params) -> builder.nullValue()));
    }

    ToXContentObject randomAllowedActions(final boolean useNullValues) {
        return useNullValues
            ? configJsonArray(generateArrayValues(useNullValues))
            : randomFrom(List.of(configJsonArray(generateArrayValues(false)), configJsonArray()));
    }
}
