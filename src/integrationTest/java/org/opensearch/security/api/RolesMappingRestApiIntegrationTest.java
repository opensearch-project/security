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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.TestRestClient;

import com.nimbusds.jose.util.Pair;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.removeOp;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.test.framework.TestSecurityConfig.Role;

public class RolesMappingRestApiIntegrationTest extends AbstractConfigEntityApiIntegrationTest {

    final static String REST_API_ADMIN_ROLES_MAPPING_ONLY = "rest-api-admin-roles-mapping-only";

    final static String REST_ADMIN_ROLE = "rest-admin-role";

    final static String REST_ADMIN_ROLE_WITH_MAPPING = "rest-admin-role-with-mapping";

    static {
        testSecurityConfig.withRestAdminUser(REST_API_ADMIN_ROLES_MAPPING_ONLY, restAdminPermission(Endpoint.ROLESMAPPING))
            .roles(
                new Role(REST_ADMIN_ROLE).reserved(true).clusterPermissions(allRestAdminPermissions()),
                new Role(REST_ADMIN_ROLE_WITH_MAPPING).clusterPermissions(allRestAdminPermissions())
            )
            .rolesMapping(new TestSecurityConfig.RoleMapping(REST_ADMIN_ROLE_WITH_MAPPING));
    }

    public RolesMappingRestApiIntegrationTest() {
        super("rolesmapping", new TestDescriptor() {
            @Override
            public ToXContentObject entityPayload(Boolean hidden, Boolean reserved, Boolean _static) {
                return roleMapping(
                    hidden,
                    reserved,
                    _static,
                    configJsonArray("a", "b"),
                    configJsonArray("c", "d"),
                    configJsonArray("e", "f"),
                    configJsonArray("g", "h")
                );
            }

            @Override
            public String entityJsonProperty() {
                return "backend_roles";
            }

            @Override
            public ToXContentObject jsonPropertyPayload() {
                return configJsonArray("a", "b");
            }

            @Override
            public Optional<String> restAdminLimitedUser() {
                return Optional.of(REST_API_ADMIN_ROLES_MAPPING_ONLY);
            }
        });
    }

    static ToXContentObject roleMappingWithUsers(ToXContentObject users) {
        return roleMapping(null, null, null, null, null, users, null);
    }

    static ToXContentObject roleMapping(
        ToXContentObject backendRoles,
        ToXContentObject hosts,
        ToXContentObject users,
        ToXContentObject andBackendRoles
    ) {
        return roleMapping(null, null, null, backendRoles, hosts, users, andBackendRoles);
    }

    static ToXContentObject roleMapping(
        final Boolean hidden,
        final Boolean reserved,
        ToXContentObject backendRoles,
        ToXContentObject hosts,
        ToXContentObject users,
        ToXContentObject andBackendRoles
    ) {
        return roleMapping(hidden, reserved, null, backendRoles, hosts, users, andBackendRoles);
    }

    static ToXContentObject roleMapping(
        final Boolean hidden,
        final Boolean reserved,
        final Boolean _static,
        ToXContentObject backendRoles,
        ToXContentObject hosts,
        ToXContentObject users,
        ToXContentObject andBackendRoles
    ) {
        return (builder, params) -> {
            builder.startObject();
            if (hidden != null) {
                builder.field("hidden", hidden);
            }
            if (reserved != null) {
                builder.field("reserved", reserved);
            }
            if (_static != null) {
                builder.field("static", _static);
            }

            builder.field("backend_roles");
            if (backendRoles != null) {
                backendRoles.toXContent(builder, params);
            } else {
                builder.startArray().endArray();
            }

            builder.field("hosts");
            if (hosts != null) {
                hosts.toXContent(builder, params);
            } else {
                builder.startArray().endArray();
            }

            builder.field("users");
            if (users != null) {
                users.toXContent(builder, params);
            } else {
                builder.startArray().endArray();
            }

            builder.field("and_backend_roles");
            if (andBackendRoles != null) {
                andBackendRoles.toXContent(builder, params);
            } else {
                builder.startArray().endArray();
            }

            return builder.endObject();
        };
    }

    String rolesApiPath(final String roleName) {
        return new StringJoiner("/").add(api()).add("roles").add(roleName).toString();
    }

    @Override
    Pair<String, String> predefinedHiddenAndReservedConfigEntities() throws Exception {
        final var hiddenEntityName = "str_hidden";
        final var reservedEntityName = "str_reserved";
        withUser(
            ADMIN_USER_NAME,
            localCluster.getAdminCertificate(),
            client -> created(() -> client.putJson(rolesApiPath(hiddenEntityName), roleJson(true, null)))
        );
        withUser(
            ADMIN_USER_NAME,
            localCluster.getAdminCertificate(),
            client -> created(
                () -> client.putJson(
                    apiPath(hiddenEntityName),
                    roleMapping(true, null, null, configJsonArray("a", "b"), configJsonArray(), configJsonArray(), configJsonArray())
                )
            )
        );
        withUser(
            ADMIN_USER_NAME,
            localCluster.getAdminCertificate(),
            client -> created(() -> client.putJson(rolesApiPath(reservedEntityName), roleJson(null, true)))
        );
        withUser(
            ADMIN_USER_NAME,
            localCluster.getAdminCertificate(),
            client -> created(
                () -> client.putJson(
                    apiPath(reservedEntityName),
                    roleMapping(null, true, null, configJsonArray("a", "b"), configJsonArray(), configJsonArray(), configJsonArray())
                )
            )
        );
        return Pair.of(hiddenEntityName, reservedEntityName);
    }

    @Override
    void creationOfReadOnlyEntityForbidden(String entityName, TestRestClient client, ToXContentObject... entities) throws Exception {
        withUser(ADMIN_USER_NAME, adminClient -> created(() -> adminClient.putJson(rolesApiPath(entityName), roleJson())));
        super.creationOfReadOnlyEntityForbidden(entityName, client, entities);
    }

    @Override
    void verifyCrudOperations(Boolean hidden, Boolean reserved, TestRestClient client) throws Exception {
        final String roleName = randomAlphanumericString();
        created(() -> client.putJson(rolesApiPath(roleName), roleJson()));

        for (ToXContentObject backendRoles : arrayOptions(false)) {
            for (ToXContentObject hosts : arrayOptions(false)) {
                for (ToXContentObject users : arrayOptions(false)) {
                    for (ToXContentObject andBackendRoles : arrayOptions(false)) {
                        verifyCrudOperationsForCombination(hidden, reserved, client, roleName, backendRoles, hosts, users, andBackendRoles);
                    }
                }
            }
        }

        // patch
        // TODO related to issue #4426
        final var newPatchRoleMappingJson = roleMapping(
            hidden,
            reserved,
            configJsonArray("a", "b"),
            configJsonArray(),
            configJsonArray(),
            configJsonArray()
        );
        ok(() -> client.patch(apiPath(), patch(addOp(roleName, newPatchRoleMappingJson))));
        assertRoleMapping(
            ok(() -> client.get(apiPath(roleName))).bodyAsJsonNode().get(roleName),
            hidden,
            reserved,
            Strings.toString(XContentType.JSON, newPatchRoleMappingJson)
        );
        ok(() -> client.patch(apiPath(roleName), patch(replaceOp("backend_roles", configJsonArray("c", "d")))));
        ok(() -> client.patch(apiPath(roleName), patch(addOp("hosts", configJsonArray("e", "f")))));
        ok(() -> client.patch(apiPath(roleName), patch(addOp("users", configJsonArray("g", "h")))));
        ok(() -> client.patch(apiPath(roleName), patch(addOp("and_backend_roles", configJsonArray("i", "j")))));
        ok(() -> client.patch(apiPath(roleName), patch(addOp("and_backend_roles", configJsonArray("i", "j")))), "No updates required");
        badRequest(() -> client.patch(apiPath(roleName), patch(replaceOp("backend_roles", configJsonArray("c", "")))));

        ok(() -> client.patch(apiPath(), patch(removeOp(roleName))));
        notFound(() -> client.get(apiPath(roleName)));
    }

    void verifyCrudOperationsForCombination(
        Boolean hidden,
        Boolean reserved,
        TestRestClient client,
        String roleName,
        ToXContentObject backendRoles,
        ToXContentObject hosts,
        ToXContentObject users,
        ToXContentObject andBackendRoles
    ) throws Exception {
        // put
        final var newPutRoleMappingJson = roleMapping(hidden, reserved, backendRoles, hosts, users, andBackendRoles);
        created(() -> client.putJson(apiPath(roleName), newPutRoleMappingJson));
        assertRoleMapping(
            ok(() -> client.get(apiPath(roleName))).bodyAsJsonNode().get(roleName),
            hidden,
            reserved,
            Strings.toString(XContentType.JSON, newPutRoleMappingJson)
        );
        final var updatePutRoleMappingJson = roleMapping(hidden, reserved, backendRoles, hosts, users, andBackendRoles);
        ok(() -> client.putJson(apiPath(roleName), updatePutRoleMappingJson));
        assertRoleMapping(
            ok(() -> client.get(apiPath(roleName))).bodyAsJsonNode().get(roleName),
            hidden,
            reserved,
            Strings.toString(XContentType.JSON, updatePutRoleMappingJson)
        );

        ok(() -> client.delete(apiPath(roleName)));
        notFound(() -> client.get(apiPath(roleName)));
    }

    void assertRoleMapping(final JsonNode actualObjectNode, final Boolean hidden, final Boolean reserved, final String expectedRoleJson)
        throws IOException {
        final var expectedObjectNode = DefaultObjectMapper.readTree(expectedRoleJson);
        final var expectedHidden = hidden != null && hidden;
        final var expectedReserved = reserved != null && reserved;
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("hidden").asBoolean(), is(expectedHidden));
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("reserved").asBoolean(), is(expectedReserved));
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("backend_roles"), is(expectedObjectNode.get("backend_roles")));
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("hosts"), is(expectedObjectNode.get("hosts")));
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("users"), is(expectedObjectNode.get("users")));
        assertThat(
            actualObjectNode.toPrettyString(),
            actualObjectNode.get("and_backend_roles"),
            is(expectedObjectNode.get("and_backend_roles"))
        );
    }

    @Override
    void verifyBadRequestOperations(TestRestClient client) throws Exception {

        final ToXContentObject unparseableJsonRequest = (builder, params) -> {
            builder.startObject();
            builder.field("unknown_json_property");
            configJsonArray("a", "b").toXContent(builder, params);
            builder.field("users");
            configJsonArray("a", "b").toXContent(builder, params);
            return builder.endObject();
        };

        notFound(
            () -> client.putJson(
                apiPath("unknown_role"),
                roleMapping(configJsonArray(), configJsonArray(), configJsonArray(), configJsonArray())
            ),
            "role 'unknown_role' not found."
        );

        // put
        badRequestWithReason(
            () -> client.putJson(apiPath(randomAlphanumericString()), EMPTY_BODY),
            "Request body required for this action."
        );
        badRequestWithReason(
            () -> client.putJson(
                apiPath(randomAlphanumericString()),
                (builder, params) -> builder.startObject().field("users", configJsonArray()).field("users", configJsonArray()).endObject()
            ),
            "Could not parse content of request."
        );
        assertInvalidKeys(
            badRequest(() -> client.putJson(apiPath(randomAlphanumericString()), unparseableJsonRequest)),
            "unknown_json_property"
        );
        for (String randomPropertyForPut : jsonProperties()) {
            assertWrongDataType(
                client.putJson(
                    apiPath(randomAlphanumericString()),
                    (builder, params) -> builder.startObject().field(randomPropertyForPut).value("something").endObject()
                ),
                Map.of(randomPropertyForPut, "Array expected")
            );
        }
        assertNullValuesInArray(
            client.putJson(
                apiPath(randomAlphanumericString()),
                roleMapping(
                    configJsonArray(generateArrayValues(true)),
                    configJsonArray(generateArrayValues(true)),
                    configJsonArray(generateArrayValues(true)),
                    configJsonArray(generateArrayValues(true))
                )
            )
        );
        // patch
        final var predefinedRole = randomAlphanumericString();
        created(() -> client.putJson(rolesApiPath(predefinedRole), roleJson()));
        created(
            () -> client.putJson(
                apiPath(predefinedRole),
                roleMapping(configJsonArray("a", "b"), configJsonArray(), configJsonArray(), configJsonArray())
            )
        );
        badRequest(() -> client.patch(apiPath(randomAlphanumericString()), EMPTY_BODY));
        badRequest(
            () -> client.patch(
                apiPath(randomAlphanumericString()),
                (builder, params) -> builder.startObject().field("users", configJsonArray()).field("users", configJsonArray()).endObject()
            )
        );
        assertInvalidKeys(
            badRequest(() -> client.patch(apiPath(), patch(addOp(randomAlphanumericString(), unparseableJsonRequest)))),
            "unknown_json_property"
        );
        badRequest(() -> client.patch(apiPath(predefinedRole), patch(replaceOp("users", unparseableJsonRequest))));
        for (String randomPropertyForPatch : jsonProperties()) {
            assertWrongDataType(
                client.patch(
                    apiPath(),
                    patch(
                        addOp(
                            randomAlphanumericString(),
                            (ToXContentObject) (builder, params) -> builder.startObject()
                                .field(randomPropertyForPatch)
                                .value("something")
                                .endObject()
                        )
                    )
                ),
                Map.of(randomPropertyForPatch, "Array expected")
            );
        }
        // TODO related to issue #4426
        assertWrongDataType(
            client.patch(apiPath(predefinedRole), patch(replaceOp("backend_roles", "something"))),
            Map.of("backend_roles", "Array expected")
        );
        assertWrongDataType(client.patch(apiPath(predefinedRole), patch(addOp("hosts", "something"))), Map.of("hosts", "Array expected"));
        assertWrongDataType(client.patch(apiPath(predefinedRole), patch(addOp("users", "something"))), Map.of("users", "Array expected"));
        assertWrongDataType(
            client.patch(apiPath(predefinedRole), patch(addOp("and_backend_roles", "something"))),
            Map.of("and_backend_roles", "Array expected")
        );
        assertNullValuesInArray(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        randomAlphanumericString(),
                        roleMapping(
                            configJsonArray(generateArrayValues(true)),
                            configJsonArray(generateArrayValues(true)),
                            configJsonArray(generateArrayValues(true)),
                            configJsonArray(generateArrayValues(true))
                        )
                    )
                )
            )
        );
        // TODO related to issue #4426
        assertNullValuesInArray(
            client.patch(apiPath(predefinedRole), patch(replaceOp("backend_roles", configJsonArray(generateArrayValues(true)))))
        );
    }

    @Override
    void forbiddenToCreateEntityWithRestAdminPermissions(TestRestClient client) throws Exception {
        for (ToXContentObject users : arrayOptions(false)) {
            forbidden(() -> client.putJson(apiPath(REST_ADMIN_ROLE), roleMappingWithUsers(users)));
            forbidden(() -> client.patch(apiPath(), patch(addOp(REST_ADMIN_ROLE, roleMappingWithUsers(users)))));
        }
    }

    @Override
    void forbiddenToUpdateAndDeleteExistingEntityWithRestAdminPermissions(TestRestClient client) throws Exception {
        // update
        for (ToXContentObject backendRoles : arrayOptions(false)) {
            for (ToXContentObject hosts : arrayOptions(false)) {
                for (ToXContentObject users : arrayOptions(false)) {
                    for (ToXContentObject andBackendRoles : arrayOptions(false)) {
                        forbidden(
                            () -> client.putJson(
                                apiPath(REST_ADMIN_ROLE_WITH_MAPPING),
                                roleMapping(backendRoles, hosts, users, andBackendRoles)
                            )
                        );
                        forbidden(
                            () -> client.patch(
                                apiPath(),
                                patch(replaceOp(REST_ADMIN_ROLE_WITH_MAPPING, roleMapping(backendRoles, hosts, users, andBackendRoles)))
                            )
                        );
                    }
                }
            }
        }
        for (ToXContentObject users : arrayOptions(false)) {
            forbidden(() -> client.patch(apiPath(REST_ADMIN_ROLE_WITH_MAPPING), patch(replaceOp("users", users))));
        }
        // remove
        forbidden(() -> client.patch(apiPath(), patch(removeOp(REST_ADMIN_ROLE_WITH_MAPPING))));
        forbidden(() -> client.patch(apiPath(REST_ADMIN_ROLE_WITH_MAPPING), patch(removeOp("users"))));
        forbidden(() -> client.delete(apiPath(REST_ADMIN_ROLE_WITH_MAPPING)));
    }

    List<String> jsonProperties() {
        return List.of("backend_roles", "hosts", "users", "and_backend_roles");
    }

    ToXContentObject roleJson() {
        return roleJson(null, null);
    }

    ToXContentObject roleJson(final Boolean hidden, final Boolean reserved) {
        return (builder, params) -> {
            builder.startObject();
            if (hidden != null) {
                builder.field("hidden", hidden);
            }
            if (reserved != null) {
                builder.field("reserved", reserved);
            }
            builder.field("cluster_permissions", configJsonArray("a", "b"));
            return builder.endObject();
        };
    }

    List<ToXContentObject> arrayOptions(final boolean useNulls) {
        return useNulls
            ? List.of(configJsonArray(generateArrayValues(useNulls)))
            : List.of(configJsonArray(generateArrayValues(false)), configJsonArray());
    }

}
