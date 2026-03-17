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
import java.util.Optional;
import java.util.StringJoiner;

import com.fasterxml.jackson.databind.JsonNode;
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
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import com.nimbusds.jose.util.Pair;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.removeOp;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.test.framework.TestSecurityConfig.Role;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class RolesMappingRestApiIntegrationTest extends AbstractConfigEntityApiIntegrationTest {

    final static TestSecurityConfig.User REST_API_ADMIN_ROLES_MAPPING_ONLY = new TestSecurityConfig.User(
        "rest-api-admin-roles-mapping-only"
    ).referencedRoles(REST_ADMIN_REST_API_ACCESS_ROLE)
        .roles(new TestSecurityConfig.Role("rest_admin_role").clusterPermissions(restAdminPermission(Endpoint.ROLESMAPPING)));

    final static String REST_ADMIN_ROLE = "rest-admin-role";

    final static String REST_ADMIN_ROLE_WITH_MAPPING = "rest-admin-role-with-mapping";

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().users(REST_API_ADMIN_ROLES_MAPPING_ONLY)
        .roles(
            new Role(REST_ADMIN_ROLE).reserved(true).clusterPermissions(allRestAdminPermissions()),
            new Role(REST_ADMIN_ROLE_WITH_MAPPING).clusterPermissions(allRestAdminPermissions())
        )
        .rolesMapping(new TestSecurityConfig.RoleMapping(REST_ADMIN_ROLE_WITH_MAPPING))
        .build();

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
                return Optional.of(REST_API_ADMIN_ROLES_MAPPING_ONLY.getName());
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
    Pair<String, String> predefinedHiddenAndReservedConfigEntities(LocalCluster localCluster) throws Exception {
        final var hiddenEntityName = "str_hidden";
        final var reservedEntityName = "str_reserved";
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            assertThat(client.putJson(rolesApiPath(hiddenEntityName), roleJson(true, null)), isCreated());
            assertThat(
                client.putJson(
                    apiPath(hiddenEntityName),
                    roleMapping(true, null, null, configJsonArray("a", "b"), configJsonArray(), configJsonArray(), configJsonArray())
                ),
                isCreated()
            );
            assertThat(client.putJson(rolesApiPath(reservedEntityName), roleJson(null, true)), isCreated());
            assertThat(
                client.putJson(
                    apiPath(reservedEntityName),
                    roleMapping(null, true, null, configJsonArray("a", "b"), configJsonArray(), configJsonArray(), configJsonArray())
                ),
                isCreated()
            );

        }

        return Pair.of(hiddenEntityName, reservedEntityName);
    }

    @Override
    void creationOfReadOnlyEntityForbidden(String entityName, TestRestClient client, ToXContentObject... entities) throws Exception {
        try (TestRestClient adminClient = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(adminClient.putJson(rolesApiPath(entityName), roleJson()), isCreated());
        }

        super.creationOfReadOnlyEntityForbidden(entityName, client, entities);
    }

    @Override
    void verifyCrudOperations(Boolean hidden, Boolean reserved, TestRestClient client) throws Exception {
        final String roleName = randomAlphanumericString();
        assertThat(client.putJson(rolesApiPath(roleName), roleJson()), isCreated());

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
        assertThat(client.patch(apiPath(), patch(addOp(roleName, newPatchRoleMappingJson))), isOk());
        assertRoleMapping(
            ok(() -> client.get(apiPath(roleName))).bodyAsJsonNode().get(roleName),
            hidden,
            reserved,
            Strings.toString(XContentType.JSON, newPatchRoleMappingJson)
        );
        assertThat(client.patch(apiPath(roleName), patch(replaceOp("backend_roles", configJsonArray("c", "d")))), isOk());
        assertThat(client.patch(apiPath(roleName), patch(addOp("hosts", configJsonArray("e", "f")))), isOk());
        assertThat(client.patch(apiPath(roleName), patch(addOp("users", configJsonArray("g", "h")))), isOk());
        assertThat(client.patch(apiPath(roleName), patch(addOp("and_backend_roles", configJsonArray("i", "j")))), isOk());
        // second identical update should still be OK; message assertion omitted
        assertThat(client.patch(apiPath(roleName), patch(addOp("and_backend_roles", configJsonArray("i", "j")))), isOk());
        assertThat(client.patch(apiPath(roleName), patch(replaceOp("backend_roles", configJsonArray("c", "")))), isBadRequest());

        assertThat(client.patch(apiPath(), patch(removeOp(roleName))), isOk());
        assertThat(client.get(apiPath(roleName)), isNotFound());
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
        assertThat(client.putJson(apiPath(roleName), newPutRoleMappingJson), isCreated());
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

        assertThat(
            client.putJson(
                apiPath("unknown_role"),
                roleMapping(configJsonArray(), configJsonArray(), configJsonArray(), configJsonArray())
            ),
            isNotFound().withAttribute("/message", "role 'unknown_role' not found.")
        );

        // put
        assertThat(
            client.putJson(apiPath(randomAlphanumericString()), EMPTY_BODY),
            isBadRequest().withAttribute("/reason", "Request body required for this action.")
        );
        assertThat(
            client.putJson(
                apiPath(randomAlphanumericString()),
                (builder, params) -> builder.startObject().field("users", configJsonArray()).field("users", configJsonArray()).endObject()
            ),
            isBadRequest().withAttribute("/reason", "Could not parse content of request.")
        );
        HttpResponse response = client.putJson(apiPath(randomAlphanumericString()), unparseableJsonRequest);
        assertThat(response, isBadRequest());
        assertInvalidKeys(response, "unknown_json_property");
        for (String randomPropertyForPut : jsonProperties()) {

            response = client.putJson(
                apiPath(randomAlphanumericString()),
                (builder, params) -> builder.startObject().field(randomPropertyForPut).value("something").endObject()
            );
            assertThat(
                response,
                isBadRequest().withAttribute("/status", "error").withAttribute("/" + randomPropertyForPut, "Array expected")
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
        assertThat(client.putJson(rolesApiPath(predefinedRole), roleJson()), isCreated());
        assertThat(
            client.putJson(
                apiPath(predefinedRole),
                roleMapping(configJsonArray("a", "b"), configJsonArray(), configJsonArray(), configJsonArray())
            ),
            isCreated()
        );
        assertThat(client.patch(apiPath(randomAlphanumericString()), EMPTY_BODY), isBadRequest());
        assertThat(
            client.patch(
                apiPath(randomAlphanumericString()),
                (builder, params) -> builder.startObject().field("users", configJsonArray()).field("users", configJsonArray()).endObject()
            ),
            isBadRequest()
        );
        response = client.patch(apiPath(), patch(addOp(randomAlphanumericString(), unparseableJsonRequest)));
        assertThat(response, isBadRequest());
        assertInvalidKeys(response, "unknown_json_property");
        assertThat(client.patch(apiPath(predefinedRole), patch(replaceOp("users", unparseableJsonRequest))), isBadRequest());
        for (String randomPropertyForPatch : jsonProperties()) {
            var resp2 = client.patch(
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
            );
            assertThat(
                resp2,
                isBadRequest().withAttribute("/status", "error").withAttribute("/" + randomPropertyForPatch, "Array expected")
            );
        }
        // TODO related to issue #4426
        var resp3 = client.patch(apiPath(predefinedRole), patch(replaceOp("backend_roles", "something")));
        assertThat(resp3, isBadRequest().withAttribute("/status", "error").withAttribute("/backend_roles", "Array expected"));
        var resp4 = client.patch(apiPath(predefinedRole), patch(addOp("hosts", "something")));
        assertThat(resp4, isBadRequest().withAttribute("/status", "error").withAttribute("/hosts", "Array expected"));
        var resp5 = client.patch(apiPath(predefinedRole), patch(addOp("users", "something")));
        assertThat(resp5, isBadRequest().withAttribute("/status", "error").withAttribute("/users", "Array expected"));
        var resp6 = client.patch(apiPath(predefinedRole), patch(addOp("and_backend_roles", "something")));
        assertThat(resp6, isBadRequest().withAttribute("/status", "error").withAttribute("/and_backend_roles", "Array expected"));
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

            assertThat(client.putJson(apiPath(REST_ADMIN_ROLE), roleMappingWithUsers(users)), isForbidden());
            assertThat(client.patch(apiPath(), patch(addOp(REST_ADMIN_ROLE, roleMappingWithUsers(users)))), isForbidden());
        }
    }

    @Override
    void forbiddenToUpdateAndDeleteExistingEntityWithRestAdminPermissions(TestRestClient client) throws Exception {
        // update
        for (ToXContentObject backendRoles : arrayOptions(false)) {
            for (ToXContentObject hosts : arrayOptions(false)) {
                for (ToXContentObject users : arrayOptions(false)) {
                    for (ToXContentObject andBackendRoles : arrayOptions(false)) {

                        assertThat(
                            client.putJson(apiPath(REST_ADMIN_ROLE_WITH_MAPPING), roleMapping(backendRoles, hosts, users, andBackendRoles)),
                            isForbidden()
                        );
                        assertThat(
                            client.patch(
                                apiPath(),
                                patch(replaceOp(REST_ADMIN_ROLE_WITH_MAPPING, roleMapping(backendRoles, hosts, users, andBackendRoles)))
                            ),
                            isForbidden()
                        );
                    }
                }
            }
        }
        for (ToXContentObject users : arrayOptions(false)) {

            assertThat(client.patch(apiPath(REST_ADMIN_ROLE_WITH_MAPPING), patch(replaceOp("users", users))), isForbidden());
        }
        // remove
        assertThat(client.patch(apiPath(), patch(removeOp(REST_ADMIN_ROLE_WITH_MAPPING))), isForbidden());
        assertThat(client.patch(apiPath(REST_ADMIN_ROLE_WITH_MAPPING), patch(removeOp("users"))), isForbidden());
        assertThat(client.delete(apiPath(REST_ADMIN_ROLE_WITH_MAPPING)), isForbidden());
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
