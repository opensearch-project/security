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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.StringJoiner;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.google.common.collect.ImmutableMap;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.dlic.rest.api.pagination.PaginationRequestParser;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.security.dlic.rest.api.InternalUsersApiAction.RESTRICTED_FROM_USERNAME;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotAllowed;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;
import static org.opensearch.test.framework.matcher.RestMatchers.isUnauthorized;

public class InternalUsersRestApiIntegrationTest extends AbstractConfigEntityApiIntegrationTest {

    final static String REST_API_ADMIN_INTERNAL_USERS_ONLY = "rest_api_admin_iternal_users_only";

    private final static String SERVICE_ACCOUNT_USER = "service_account_user";

    private final static String HIDDEN_ROLE = "hidden-role";

    private final static String RESERVED_ROLE = "reserved-role";

    private final static String SOME_ROLE = "some-role";

    private final static String LEGACY_EMPTY_BACKEND_ROLES_USER = "legacy_empty_backend_roles_user";

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().users(
        new TestSecurityConfig.User(SERVICE_ACCOUNT_USER).attr("service", "true").attr("enabled", "true"),
        new TestSecurityConfig.User(REST_API_ADMIN_INTERNAL_USERS_ONLY).referencedRoles(
            new TestSecurityConfig.Role(REST_API_ADMIN_INTERNAL_USERS_ONLY)
        ).roles(new TestSecurityConfig.Role("rest_admin_role").clusterPermissions(restAdminPermission(Endpoint.INTERNALUSERS))),
        new TestSecurityConfig.User(LEGACY_EMPTY_BACKEND_ROLES_USER).backendRoles("", "admin")
    )
        .roles(
            new TestSecurityConfig.Role(HIDDEN_ROLE).hidden(true),
            new TestSecurityConfig.Role(RESERVED_ROLE).reserved(true),
            new TestSecurityConfig.Role(SOME_ROLE),
            new TestSecurityConfig.Role(REST_API_ADMIN_INTERNAL_USERS_ONLY)
        )
        .build();

    public InternalUsersRestApiIntegrationTest() {
        super("internalusers", new TestDescriptor() {

            @Override
            public ToXContentObject entityPayload(Boolean hidden, Boolean reserved, Boolean _static) {
                return internalUser(hidden, reserved, _static, "rv2fR924a149ava32", null, null, null);
            }

            @Override
            public String entityJsonProperty() {
                return "backend_roles";
            }

            @Override
            public ToXContentObject jsonPropertyPayload() {
                return (builder, params) -> builder.startArray().value("a").endArray();
            }

            @Override
            public Optional<String> restAdminLimitedUser() {
                return Optional.of(REST_API_ADMIN_INTERNAL_USERS_ONLY);
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

    static ToXContentObject internalUserWithPassword(final String password) {
        return internalUser(null, null, null, password, null, null, null);
    }

    static ToXContentObject internalUser(
        final Boolean hidden,
        final Boolean reserved,
        final String password,
        final ToXContentObject backendRoles,
        final ToXContentObject attributes,
        final ToXContentObject securityRoles
    ) {
        return internalUser(hidden, reserved, null, password, backendRoles, attributes, securityRoles);
    }

    static ToXContentObject internalUser(
        final String password,
        final ToXContentObject backendRoles,
        final ToXContentObject attributes,
        final ToXContentObject securityRoles
    ) {
        return internalUser(null, null, null, password, backendRoles, attributes, securityRoles);
    }

    static ToXContentObject internalUser(
        final Boolean hidden,
        final Boolean reserved,
        final Boolean _static,
        final String password,
        final ToXContentObject backendRoles,
        final ToXContentObject attributes,
        final ToXContentObject securityRoles
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
            if (password == null) {
                builder.field("password").nullValue();
            } else {
                builder.field("password", password);
            }
            if (backendRoles != null) {
                builder.field("backend_roles");
                backendRoles.toXContent(builder, params);
            }
            if (attributes != null) {
                builder.field("attributes", attributes);
            }
            if (securityRoles != null) {
                builder.field("opendistro_security_roles");
                securityRoles.toXContent(builder, params);
            }
            return builder.endObject();
        };
    }

    static ToXContentObject defaultServiceUser() {
        return serviceUser(null, null, null); // default user is disabled
    }

    static ToXContentObject serviceUserWithPassword(final Boolean enabled, final String password) {
        return serviceUser(enabled, password, null);
    }

    static ToXContentObject serviceUserWithHash(final Boolean enabled, final String hash) {
        return serviceUser(enabled, null, hash);
    }

    static ToXContentObject serviceUser(final Boolean enabled) {
        return serviceUser(enabled, null, null);
    }

    static ToXContentObject serviceUser(final Boolean enabled, final String password, final String hash) {
        return (builder, params) -> {
            builder.startObject();
            if (password != null) {
                builder.field("password", password);
            }
            if (hash != null) {
                builder.field("hash", hash);
            }
            final var attributes = ImmutableMap.builder().put("service", "true");
            if (enabled != null) {
                attributes.put("enabled", enabled);
            }
            builder.field("attributes", attributes.build());
            return builder.endObject();
        };
    }

    @Override
    void verifyBadRequestOperations(TestRestClient client) throws Exception {
        // bad query string parameter name
        assertThat(client.get(apiPath() + "?aaaaa=bbbbb"), isBadRequest());
        final var predefinedUserName = randomAsciiAlphanumOfLength(4);
        assertThat(
            client.putJson(
                apiPath(predefinedUserName),
                internalUser(randomAsciiAlphanumOfLength(10), configJsonArray(generateArrayValues(false)), null, null)
            ),
            isCreated()
        );
        invalidJson(client, predefinedUserName);
    }

    void invalidJson(final TestRestClient client, final String predefinedUserName) throws Exception {
        // put
        assertThat(client.putJson(apiPath(randomAsciiAlphanumOfLength(5)), EMPTY_BODY), isBadRequest());
        assertThat(client.putJson(apiPath(randomAsciiAlphanumOfLength(5)), (builder, params) -> {
            builder.startObject();
            builder.field("backend_roles");
            randomConfigArray(false).toXContent(builder, params);
            builder.field("backend_roles");
            randomConfigArray(false).toXContent(builder, params);
            return builder.endObject();
        }), isBadRequest());
        HttpResponse response = client.putJson(apiPath(randomAsciiAlphanumOfLength(5)), (builder, params) -> {
            builder.startObject();
            builder.field("unknown_json_property");
            configJsonArray("a", "b").toXContent(builder, params);
            builder.field("backend_roles");
            randomConfigArray(false).toXContent(builder, params);
            return builder.endObject();
        });
        assertThat(response, isBadRequest());
        assertInvalidKeys(response, "unknown_json_property");

        response = client.putJson(
            apiPath(randomAsciiAlphanumOfLength(10)),
            (builder, params) -> builder.startObject()
                .field("password", configJsonArray("a", "b"))
                .field("hash")
                .nullValue()
                .field("backend_roles", "c")
                .field("attributes", "d")
                .field("opendistro_security_roles", "e")
                .endObject()
        );
        assertThat(
            response,
            isBadRequest().withAttribute("/status", "error")
                .withAttribute("/password", "String expected")
                .withAttribute("/hash", "String expected")
                .withAttribute("/backend_roles", "Array expected")
                .withAttribute("/attributes", "Object expected")
                .withAttribute("/opendistro_security_roles", "Array expected")
        );
        assertNullValuesInArray(
            client.putJson(
                apiPath(randomAsciiAlphanumOfLength(10)),
                (builder, params) -> builder.startObject().field("backend_roles", configJsonArray(generateArrayValues(true))).endObject()
            )
        );
        assertNullValuesInArray(
            client.putJson(
                apiPath(randomAsciiAlphanumOfLength(10)),
                (builder, params) -> builder.startObject().field("backend_roles", configJsonArray("a", "")).endObject()
            )
        );
        // patch
        assertThat(client.patch(apiPath(), patch(addOp(randomAsciiAlphanumOfLength(10), EMPTY_BODY))), isBadRequest());
        for (String field : List.of("opendistro_security_roles", "backend_roles", "attributes")) {

            assertThat(client.patch(apiPath(predefinedUserName), patch(replaceOp(field, EMPTY_BODY))), isBadRequest());
        }
        assertThat(client.patch(apiPath(), patch(addOp(randomAsciiAlphanumOfLength(5), (ToXContentObject) (builder, params) -> {
            builder.startObject();
            builder.field("unknown_json_property");
            configJsonArray("a", "b").toXContent(builder, params);
            builder.field("backend_roles");
            randomConfigArray(false).toXContent(builder, params);
            return builder.endObject();
        }))), isBadRequest());
        assertWrongDataType(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        randomAsciiAlphanumOfLength(10),
                        (ToXContentObject) (builder, params) -> builder.startObject()
                            .field("password", configJsonArray("a", "b"))
                            .field("hash")
                            .nullValue()
                            .field("backend_roles", "c")
                            .field("attributes", "d")
                            .field("opendistro_security_roles", "e")
                            .endObject()
                    )
                )
            ),
            Map.of(
                "password",
                "String expected",
                "hash",
                "String expected",
                "backend_roles",
                "Array expected",
                "attributes",
                "Object expected",
                "opendistro_security_roles",
                "Array expected"
            )
        );
        // TODO related to issue #4426
        assertWrongDataType(
            client.patch(apiPath(predefinedUserName), patch(replaceOp("backend_roles", "a"))),
            Map.of("backend_roles", "Array expected")
        );
        assertNullValuesInArray(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        randomAsciiAlphanumOfLength(5),
                        internalUser(randomAsciiAlphanumOfLength(10), randomConfigArray(true), null, randomConfigArray(true))
                    )
                )
            )
        );
        // TODO related to issue #4426
        assertNullValuesInArray(client.patch(apiPath(predefinedUserName), patch(replaceOp("backend_roles", randomConfigArray(true)))));
    }

    @Override
    void verifyCrudOperations(Boolean hidden, Boolean reserved, TestRestClient client) throws Exception {
        for (ToXContentObject attributes : attributesOptions()) {
            for (ToXContentObject securityRoles : securityRolesOptions()) {
                verifyCrudOperationsForCombination(hidden, reserved, client, attributes, securityRoles);
            }
        }
    }

    void verifyCrudOperationsForCombination(
        Boolean hidden,
        Boolean reserved,
        TestRestClient client,
        ToXContentObject attributes,
        ToXContentObject securityRoles
    ) throws Exception {
        // put
        final var usernamePut = randomAsciiAlphanumOfLength(10);
        final var newUserJsonPut = internalUser(
            hidden,
            reserved,
            randomAsciiAlphanumOfLength(10),
            randomConfigArray(false),
            attributes,
            securityRoles
        );
        assertThat(client.putJson(apiPath(usernamePut), newUserJsonPut), isCreated());
        assertInternalUser(
            ok(() -> client.get(apiPath(usernamePut))).bodyAsJsonNode().get(usernamePut),
            hidden,
            reserved,
            Strings.toString(XContentType.JSON, newUserJsonPut)
        );
        final var updatedUserJsonPut = internalUser(
            hidden,
            reserved,
            randomAsciiAlphanumOfLength(10),
            randomConfigArray(false),
            attributes,
            securityRoles
        );
        assertThat(client.putJson(apiPath(usernamePut), updatedUserJsonPut), isOk());
        assertInternalUser(
            ok(() -> client.get(apiPath(usernamePut))).bodyAsJsonNode().get(usernamePut),
            hidden,
            reserved,
            Strings.toString(XContentType.JSON, updatedUserJsonPut)
        );
        assertThat(client.delete(apiPath(usernamePut)), isOk());
        assertThat(client.get(apiPath(usernamePut)), isNotFound());
        // patch
        // TODO related to issue #4426
        final var usernamePatch = randomAsciiAlphanumOfLength(10);
        final var newUserJsonPatch = internalUser(
            hidden,
            reserved,
            randomAsciiAlphanumOfLength(10),
            configJsonArray("a", "b"),
            (builder, params) -> builder.startObject().endObject(),
            configJsonArray()
        );
        assertThat(client.patch(apiPath(), patch(addOp(usernamePatch, newUserJsonPatch))), isOk());
        assertInternalUser(
            ok(() -> client.get(apiPath(usernamePatch))).bodyAsJsonNode().get(usernamePatch),
            hidden,
            reserved,
            Strings.toString(XContentType.JSON, newUserJsonPatch)
        );
        assertThat(client.patch(apiPath(usernamePatch), patch(replaceOp("backend_roles", configJsonArray("c", "d")))), isOk());
        assertThat(
            client.patch(
                apiPath(usernamePatch),
                patch(addOp("attributes", (ToXContentObject) (builder, params) -> builder.startObject().field("a", "b").endObject()))
            ),
            isOk()
        );
        assertThat(
            client.patch(apiPath(usernamePatch), patch(addOp("opendistro_security_roles", configJsonArray(RESERVED_ROLE, SOME_ROLE)))),
            isOk()
        );
    }

    List<ToXContentObject> attributesOptions() {
        return List.of(
            (builder, params) -> builder.startObject().endObject(),
            (builder, params) -> builder.startObject().field("a", "b").field("c", "d").endObject()
        );
    }

    List<ToXContentObject> securityRolesOptions() {
        return List.of(configJsonArray(), configJsonArray(SOME_ROLE, RESERVED_ROLE));
    }

    void assertInternalUser(
        final JsonNode actualObjectNode,
        final Boolean hidden,
        final Boolean reserved,
        final String expectedInternalUserJson
    ) throws IOException {
        final var expectedObjectNode = DefaultObjectMapper.readTree(expectedInternalUserJson);
        final var expectedHidden = hidden != null && hidden;
        final var expectedReserved = reserved != null && reserved;
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("hidden").asBoolean(), is(expectedHidden));
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("reserved").asBoolean(), is(expectedReserved));
        assertThat(actualObjectNode.toPrettyString(), not(actualObjectNode.has("hash")));
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("backend_roles"), is(expectedObjectNode.get("backend_roles")));
        assertThat(actualObjectNode.toPrettyString(), actualObjectNode.get("attributes"), is(expectedObjectNode.get("attributes")));
        assertThat(
            actualObjectNode.toPrettyString(),
            actualObjectNode.get("opendistro_security_roles"),
            is(expectedObjectNode.get("opendistro_security_roles"))
        );
    }

    String filterBy(final String value) {
        return apiPath() + "?filterBy=" + value;
    }

    @Test
    public void filters() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertFilterByUsers(ok(() -> client.get(apiPath())), true, true);
            assertFilterByUsers(ok(() -> client.get(filterBy("any"))), true, true);
            assertFilterByUsers(ok(() -> client.get(filterBy("internal"))), false, true);
            assertFilterByUsers(ok(() -> client.get(filterBy("service"))), true, false);
            assertFilterByUsers(ok(() -> client.get(filterBy("something"))), true, true);
        }
    }

    void assertFilterByUsers(final HttpResponse response, final boolean hasServiceUser, final boolean hasInternalUser) {
        assertThat(response.getBody(), response.bodyAsJsonNode().has(SERVICE_ACCOUNT_USER), is(hasServiceUser));
        assertThat(response.getBody(), response.bodyAsJsonNode().has(NEW_USER.getName()), is(hasInternalUser));
    }

    @Test
    public void paginatedFilterByServiceReturnsOnlyServiceUsers() throws Exception {
        final String SIZE = PaginationRequestParser.PARAM_SIZE;
        final String FILTER_BY = "filterBy";
        final String NEXT = PaginationRequestParser.RESPONSE_NEXT_TOKEN_KEY;
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Collect all names from a full paginated traversal with filterBy=service
            final var allSeen = new ArrayList<String>();
            String nextToken = null;
            do {
                final String path = (nextToken == null)
                    ? apiPath() + "?" + SIZE + "=100&" + FILTER_BY + "=service"
                    : apiPath()
                        + "?"
                        + SIZE
                        + "=100&"
                        + FILTER_BY
                        + "=service&"
                        + PaginationRequestParser.PARAM_NEXT_TOKEN
                        + "="
                        + nextToken;
                final var body = ok(() -> client.get(path)).bodyAsJsonNode();
                assertThat("paginated response must have internalusers key", body.has("internalusers"), is(true));
                body.get("internalusers").propertyNames().forEach(allSeen::add);
                nextToken = body.get(NEXT).isNull() ? null : body.get(NEXT).asText();
            } while (nextToken != null);

            assertThat("service user must appear in filterBy=service paginated result", allSeen.contains(SERVICE_ACCOUNT_USER), is(true));
            assertThat(
                "internal user must NOT appear in filterBy=service paginated result",
                allSeen.contains(NEW_USER.getName()),
                is(false)
            );
        }
    }

    @Test
    public void paginatedFilterByInternalReturnsOnlyInternalUsers() throws Exception {
        final String SIZE = PaginationRequestParser.PARAM_SIZE;
        final String FILTER_BY = "filterBy";
        final String NEXT = PaginationRequestParser.RESPONSE_NEXT_TOKEN_KEY;
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final var allSeen = new ArrayList<String>();
            String nextToken = null;
            do {
                final String path = (nextToken == null)
                    ? apiPath() + "?" + SIZE + "=100&" + FILTER_BY + "=internal"
                    : apiPath()
                        + "?"
                        + SIZE
                        + "=100&"
                        + FILTER_BY
                        + "=internal&"
                        + PaginationRequestParser.PARAM_NEXT_TOKEN
                        + "="
                        + nextToken;
                final var body = ok(() -> client.get(path)).bodyAsJsonNode();
                body.get("internalusers").propertyNames().forEach(allSeen::add);
                nextToken = body.get(NEXT).isNull() ? null : body.get(NEXT).asText();
            } while (nextToken != null);

            assertThat("internal user must appear in filterBy=internal paginated result", allSeen.contains(NEW_USER.getName()), is(true));
            assertThat(
                "service user must NOT appear in filterBy=internal paginated result",
                allSeen.contains(SERVICE_ACCOUNT_USER),
                is(false)
            );
        }
    }

    @Test
    public void verifyPOSTOnlyForAuthTokenEndpoint() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.post(apiPath(ADMIN_USER.getName(), "authtoken")), isBadRequest());
            assertThat(client.post(apiPath(SERVICE_ACCOUNT_USER, "authtoken")), isOk());
            /*
              should be notImplement but the call doesn't reach {@link org.opensearch.security.dlic.rest.api.InternalUsersApiAction#withAuthTokenPath(RestRequest)}
             */
            assertThat(client.post(apiPath("randomPath")), isNotAllowed());
        }
    }

    @Test
    public void userApiWithDotsInName() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            for (final var dottedUserName : List.of(".my.dotuser0", ".my.dot.user0")) {
                assertThat(
                    client.putJson(
                        apiPath(dottedUserName),
                        (builder, params) -> builder.startObject().field("password", randomAsciiAlphanumOfLength(10)).endObject()
                    ),
                    isCreated()
                );
            }
            for (final var dottedUserName : List.of(".my.dotuser1", ".my.dot.user1")) {
                assertThat(
                    client.putJson(
                        apiPath(dottedUserName),
                        (builder, params) -> builder.startObject()
                            .field("hash", passwordHasher.hash(randomAsciiAlphanumOfLength(10).toCharArray()))
                            .endObject()
                    ),
                    isCreated()
                );
            }
            for (final var dottedUserName : List.of(".my.dotuser2", ".my.dot.user2")) {
                assertThat(
                    client.patch(
                        apiPath(),
                        patch(
                            addOp(
                                dottedUserName,
                                (ToXContentObject) (builder, params) -> builder.startObject()
                                    .field("password", randomAsciiAlphanumOfLength(10))
                                    .endObject()
                            )
                        )
                    ),
                    isOk()
                );
            }
            for (final var dottedUserName : List.of(".my.dotuser3", ".my.dot.user3")) {
                assertThat(
                    client.patch(
                        apiPath(),
                        patch(
                            addOp(
                                dottedUserName,
                                (ToXContentObject) (builder, params) -> builder.startObject()
                                    .field("hash", passwordHasher.hash(randomAsciiAlphanumOfLength(10).toCharArray()))
                                    .endObject()
                            )
                        )
                    ),
                    isOk()
                );
            }
        }
    }

    @Test
    public void noPasswordChange() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(
                client.putJson(
                    apiPath("user1"),
                    (builder, params) -> builder.startObject()
                        .field("hash", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m")
                        .endObject()
                ),
                isCreated()
            );
            assertThat(
                client.putJson(
                    apiPath("user1"),
                    (builder, params) -> builder.startObject()
                        .field("hash", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m")
                        .field("password", "")
                        .field("backend_roles", configJsonArray("admin", "role_a"))
                        .endObject()
                ),
                isBadRequest()
            );
            assertThat(
                client.putJson(
                    apiPath("user1"),
                    (builder, params) -> builder.startObject()
                        .field("hash", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m")
                        .field("password", randomAsciiAlphanumOfLength(10))
                        .field("backend_roles", configJsonArray("admin", "role_a"))
                        .endObject()
                ),
                isOk()
            );
            assertThat(
                client.putJson(
                    apiPath("user2"),
                    (builder, params) -> builder.startObject()
                        .field("hash", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m")
                        .field("password", randomAsciiAlphanumOfLength(10))
                        .endObject()
                ),
                isCreated()
            );
            assertThat(
                client.putJson(
                    apiPath("user2"),
                    (builder, params) -> builder.startObject()
                        .field("password", "")
                        .field("backend_roles", configJsonArray("admin", "role_b"))
                        .endObject()
                ),
                isBadRequest()
            );
            assertThat(
                client.putJson(
                    apiPath("user2"),
                    (builder, params) -> builder.startObject()
                        .field("password", randomAsciiAlphanumOfLength(10))
                        .field("backend_roles", configJsonArray("admin", "role_b"))
                        .endObject()
                ),
                isOk()
            );
        }
    }

    @Test
    public void securityRoles() throws Exception {
        final var userWithSecurityRoles = randomAsciiAlphanumOfLength(15);
        final var userWithSecurityRolesPassword = randomAsciiAlphanumOfLength(10);
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(
                client.patch(apiPath(), patch(addOp(userWithSecurityRoles, internalUser(userWithSecurityRolesPassword, null, null, null)))),
                isOk()
            );
        }

        try (TestRestClient client = localCluster.getRestClient(userWithSecurityRoles, userWithSecurityRolesPassword)) {
            assertThat(client.get(apiPath()), isForbidden());
        }

        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(
                client.patch(
                    apiPath(),
                    patch(
                        replaceOp(
                            userWithSecurityRoles,
                            internalUser(
                                userWithSecurityRolesPassword,
                                null,
                                null,
                                (builder, params) -> builder.startArray().value("user_admin__all_access").endArray()
                            )
                        )
                    )
                ),
                isOk()
            );
        }

        try (TestRestClient client = localCluster.getRestClient(userWithSecurityRoles, userWithSecurityRolesPassword)) {
            assertThat(client.get(apiPath()), isOk());
        }

        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            impossibleToSetHiddenRoleIsNotAllowed(userWithSecurityRoles, client);
            settingOfUnknownRoleIsNotAllowed(userWithSecurityRoles, client);
        }

        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            settingOfUnknownRoleIsNotAllowed(userWithSecurityRoles, client);
            canAssignedHiddenRole(client);
        }

        try (TestRestClient client = localCluster.getRestClient(REST_ADMIN_USER)) {
            settingOfUnknownRoleIsNotAllowed(userWithSecurityRoles, client);
            canAssignedHiddenRole(client);
        }

        try (TestRestClient client = localCluster.getRestClient(REST_API_ADMIN_INTERNAL_USERS_ONLY, DEFAULT_PASSWORD)) {
            settingOfUnknownRoleIsNotAllowed(userWithSecurityRoles, client);
            canAssignedHiddenRole(client);
        }
    }

    void impossibleToSetHiddenRoleIsNotAllowed(final String predefinedUserName, final TestRestClient client) throws Exception {
        // put
        assertThat(
            client.putJson(
                apiPath(randomAsciiAlphanumOfLength(10)),
                internalUser(randomAsciiAlphanumOfLength(10), null, null, configJsonArray(HIDDEN_ROLE))
            ),
            isNotFound().withAttribute("/message", "Resource 'hidden-role' is not available.")
        );
        // patch
        assertThat(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        randomAsciiAlphanumOfLength(10),
                        internalUser(randomAsciiAlphanumOfLength(10), null, null, configJsonArray(HIDDEN_ROLE))
                    )
                )
            ),
            isNotFound()
        );
        // TODO related to issue #4426
        assertThat(
            client.patch(apiPath(predefinedUserName), patch(addOp("opendistro_security_roles", configJsonArray(HIDDEN_ROLE)))),
            isNotFound()
        );
    }

    void canAssignedHiddenRole(final TestRestClient client) throws Exception {
        final var userNamePut = randomAsciiAlphanumOfLength(4);
        assertThat(
            client.putJson(apiPath(userNamePut), internalUser(randomAsciiAlphanumOfLength(10), null, null, configJsonArray(HIDDEN_ROLE))),
            isCreated()
        );
    }

    void settingOfUnknownRoleIsNotAllowed(final String predefinedUserName, final TestRestClient client) throws Exception {
        assertThat(
            client.putJson(
                apiPath(randomAsciiAlphanumOfLength(10)),
                internalUser(randomAsciiAlphanumOfLength(10), null, null, configJsonArray("unknown-role"))
            ),
            isNotFound().withAttribute("/message", "role 'unknown-role' not found.")
        );
        assertThat(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        randomAsciiAlphanumOfLength(4),
                        internalUser(randomAsciiAlphanumOfLength(10), null, null, configJsonArray("unknown-role"))
                    )
                )
            ),
            isNotFound()
        );
        assertThat(
            client.patch(apiPath(predefinedUserName), patch(addOp("opendistro_security_roles", configJsonArray("unknown-role")))),
            isNotFound()
        );
    }

    @Test
    public void parallelPutRequests() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final var userName = randomAsciiAlphanumOfLength(10);
            final var httpResponses = new HttpResponse[10];

            try (final var executorService = Executors.newFixedThreadPool(httpResponses.length)) {
                final var futures = new ArrayList<Future<HttpResponse>>(httpResponses.length);
                for (int i = 0; i < httpResponses.length; i++) {
                    futures.add(
                        executorService.submit(
                            () -> client.putJson(
                                apiPath(userName),
                                (builder, params) -> builder.startObject().field("password", randomAsciiAlphanumOfLength(10)).endObject()
                            )
                        )
                    );
                }
                for (int i = 0; i < httpResponses.length; i++) {
                    httpResponses[i] = futures.get(i).get();
                }
            }
            boolean created = false;
            for (HttpResponse response : httpResponses) {
                int sc = response.getStatusCode();
                switch (sc) {
                    case HttpStatus.SC_CREATED:
                        Assert.assertFalse(created);
                        created = true;
                        break;
                    case HttpStatus.SC_OK:
                        break;
                    default:
                        assertThat(sc, is(HttpStatus.SC_CONFLICT));
                        break;
                }
            }
        }
    }

    @Test
    public void restrictedUsernameContents() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            {
                for (final var restrictedTerm : RESTRICTED_FROM_USERNAME) {
                    for (final var username : List.of(
                        randomAsciiAlphanumOfLength(2) + restrictedTerm + randomAsciiAlphanumOfLength(3),
                        URLEncoder.encode(randomAsciiAlphanumOfLength(4) + ":" + randomAsciiAlphanumOfLength(3), StandardCharsets.UTF_8)
                    )) {
                        assertThat(
                            client.putJson(apiPath(username), internalUserWithPassword(randomAsciiAlphanumOfLength(10))),
                            isBadRequest("/message", restrictedTerm)
                        );
                        assertThat(
                            client.patch(apiPath(), patch(addOp(username, internalUserWithPassword(randomAsciiAlphanumOfLength(10))))),
                            isBadRequest("/message", restrictedTerm)
                        );
                    }
                }
            }
        }
    }

    @Test
    public void serviceUsers() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Add enabled service account then get it
            // TODO related to issue #4426 add default behave when enabled is true
            final var happyServiceLiveUserName = randomAsciiAlphanumOfLength(10);
            assertThat(client.putJson(apiPath(happyServiceLiveUserName), serviceUser(true)), isCreated());
            final var serviceLiveResponse = client.get(apiPath(happyServiceLiveUserName));
            assertThat(serviceLiveResponse, isOk());
            assertThat(
                serviceLiveResponse.getBody(),
                serviceLiveResponse.getBooleanFromJsonBody("/" + happyServiceLiveUserName + "/attributes/service")
            );
            assertThat(
                serviceLiveResponse.getBody(),
                serviceLiveResponse.getBooleanFromJsonBody("/" + happyServiceLiveUserName + "/attributes/enabled")
            );

            // Add disabled service account
            final var happyServiceDeadUserName = randomAsciiAlphanumOfLength(10);
            assertThat(client.putJson(apiPath(happyServiceDeadUserName), serviceUser(false)), isCreated());
            final var serviceDeadResponse = client.get(apiPath(happyServiceDeadUserName));
            assertThat(serviceDeadResponse, isOk());
            assertThat(
                serviceDeadResponse.getBody(),
                serviceDeadResponse.getBooleanFromJsonBody("/" + happyServiceDeadUserName + "/attributes/service")
            );
            assertThat(
                serviceDeadResponse.getBody(),
                not(serviceDeadResponse.getBooleanFromJsonBody("/" + happyServiceDeadUserName + "/attributes/enabled"))
            );
            // Add service account with password -- Should Fail
            assertThat(
                client.putJson(apiPath(randomAsciiAlphanumOfLength(10)), serviceUserWithPassword(true, randomAsciiAlphanumOfLength(10))),
                isBadRequest()
            );
            // Add service with hash -- should fail
            assertThat(
                client.putJson(
                    apiPath(randomAsciiAlphanumOfLength(10)),
                    serviceUserWithHash(true, passwordHasher.hash(randomAsciiAlphanumOfLength(10).toCharArray()))
                ),
                isBadRequest()
            );
            // Add Service account with password & Hash -- should fail
            final var password = randomAsciiAlphanumOfLength(10);
            assertThat(
                client.putJson(
                    apiPath(randomAsciiAlphanumOfLength(10)),
                    serviceUser(true, password, passwordHasher.hash(password.toCharArray()))
                ),
                isBadRequest()
            );
        }
    }

    @Test
    public void bulkPatchChangingHashDoesNotRevalidateUnchangedBackendRoles() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Bulk PATCH only the hash on a user with legacy empty-string backend_roles —
            // should succeed without revalidating the unchanged backend_roles
            assertThat(
                client.patch(
                    apiPath(),
                    patch(
                        replaceOp(LEGACY_EMPTY_BACKEND_ROLES_USER + "/hash", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m")
                    )
                ),
                isOk()
            );
            // Bulk PATCH that changes backend_roles with blank values — should still be rejected
            assertThat(
                client.patch(
                    apiPath(),
                    patch(replaceOp(LEGACY_EMPTY_BACKEND_ROLES_USER + "/backend_roles", configJsonArray("", "new_role")))
                ),
                isBadRequest()
            );
        }
    }

    // The rename route is only registered under /_plugins, so these tests use a fixed prefix instead of apiPath().
    private static String securityApi(final String... path) {
        final var fullPath = new StringJoiner("/").add(PLUGINS_PREFIX).add("api");
        for (final var p : path) {
            fullPath.add(p);
        }
        return fullPath.toString();
    }

    private static String renamePath(final String username) {
        return securityApi("internalusers", username, "_rename");
    }

    private static ToXContentObject renameBody(final String newUsername) {
        return (builder, params) -> builder.startObject().field("new_username", newUsername).endObject();
    }

    /** Creates an empty role and a role mapping that lists the given users explicitly. */
    private static void createRoleMappedToUsers(final TestRestClient client, final String role, final String... users) {
        assertThat(
            client.putJson(
                securityApi("roles", role),
                (builder, params) -> builder.startObject().field("description", "rename test").endObject()
            ),
            isCreated()
        );
        assertThat(
            client.putJson(securityApi("rolesmapping", role), (builder, params) -> builder.startObject().array("users", users).endObject()),
            isCreated()
        );
    }

    private static List<String> mappedUsers(final TestRestClient client, final String role) {
        final var response = client.get(securityApi("rolesmapping", role));
        assertThat(response, isOk());
        final List<String> users = new ArrayList<>();
        response.bodyAsJsonNode().get(role).get("users").forEach(user -> users.add(user.asText()));
        return users;
    }

    @Test
    public void renameMovesUserAndExplicitRoleMappingReferences() throws Exception {
        final var oldName = "rename_src_" + randomAsciiAlphanumOfLength(8);
        final var newName = "rename_dst_" + randomAsciiAlphanumOfLength(8);
        final var otherUser = "rename_other_" + randomAsciiAlphanumOfLength(8);
        final var mappedRole = "rename_role_" + randomAsciiAlphanumOfLength(8);
        final var unrelatedRole = "rename_unrelated_" + randomAsciiAlphanumOfLength(8);
        final var password = randomAsciiAlphanumOfLength(12);

        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.putJson(apiPath(oldName), internalUserWithPassword(password)), isCreated());
            createRoleMappedToUsers(client, mappedRole, oldName, otherUser);
            createRoleMappedToUsers(client, unrelatedRole, otherUser);

            final var response = client.postJson(renamePath(oldName), renameBody(newName));
            assertThat(response, isOk());
            assertThat(response.getTextFromJsonBody("/previous_username"), is(oldName));
            assertThat(response.getTextFromJsonBody("/username"), is(newName));
            assertThat(response.getTextFromJsonBody("/updated_roles_mapping/0"), is(mappedRole));
            assertThat(response.bodyAsJsonNode().get("updated_roles_mapping").size(), is(1));

            // Document 1: the user record moved.
            assertThat(client.get(apiPath(oldName)), isNotFound());
            assertThat(client.get(apiPath(newName)), isOk());
            // Document 2: explicit references rewritten in place; mappings that don't name the user are untouched.
            assertThat(mappedUsers(client, mappedRole), is(List.of(newName, otherUser)));
            assertThat(mappedUsers(client, unrelatedRole), is(List.of(otherUser)));
        }

        // After the reload, every node sees both changes: the new name logs in with the old password and keeps its role.
        try (TestRestClient renamed = localCluster.getRestClient(newName, password)) {
            final var authInfo = renamed.getAuthInfo();
            assertThat(authInfo, isOk());
            final List<String> roles = new ArrayList<>();
            authInfo.bodyAsJsonNode().get("roles").forEach(role -> roles.add(role.asText()));
            assertThat(roles.contains(mappedRole), is(true));
        }
        try (TestRestClient old = localCluster.getRestClient(oldName, password)) {
            assertThat(old.getAuthInfo(), isUnauthorized());
        }
    }

    @Test
    public void renameRejectsInvalidRequestsWithoutChangingAnything() throws Exception {
        final var source = "rename_src_" + randomAsciiAlphanumOfLength(8);
        final var taken = "rename_taken_" + randomAsciiAlphanumOfLength(8);
        final var role = "rename_role_" + randomAsciiAlphanumOfLength(8);
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.putJson(apiPath(source), internalUserWithPassword(randomAsciiAlphanumOfLength(12))), isCreated());
            assertThat(client.putJson(apiPath(taken), internalUserWithPassword(randomAsciiAlphanumOfLength(12))), isCreated());
            createRoleMappedToUsers(client, role, source);

            // Source must exist.
            assertThat(client.postJson(renamePath("rename_missing_" + randomAsciiAlphanumOfLength(8)), renameBody("x")), isNotFound());
            // Destination must be free.
            assertThat(client.postJson(renamePath(source), renameBody(taken)).getStatusCode(), is(HttpStatus.SC_CONFLICT));
            // Body must be exactly {"new_username": <valid name>}.
            assertThat(client.postJson(renamePath(source), EMPTY_BODY), isBadRequest());
            assertThat(
                client.postJson(
                    renamePath(source),
                    (builder, params) -> builder.startObject().field("new_username", "x").field("unexpected", "y").endObject()
                ),
                isBadRequest()
            );
            assertThat(client.postJson(renamePath(source), renameBody("")), isBadRequest());
            // The shared request validator rejects a value that is not a string.
            assertThat(
                client.postJson(renamePath(source), (builder, params) -> builder.startObject().nullField("new_username").endObject()),
                isBadRequest("/reason", "Wrong datatype")
            );
            assertThat(
                client.postJson(renamePath(source), (builder, params) -> builder.startObject().field("new_username", 123).endObject()),
                isBadRequest("/reason", "Wrong datatype")
            );
            assertThat(client.postJson(renamePath(source), renameBody("a:b")), isBadRequest("/message", ":"));
            assertThat(client.postJson(renamePath(source), renameBody(source)), isBadRequest());

            // None of the rejected requests changed either document.
            assertThat(client.get(apiPath(source)), isOk());
            assertThat(client.get(apiPath(taken)), isOk());
            assertThat(mappedUsers(client, role), is(List.of(source)));
        }
    }

    @Test
    public void renameRespectsAccessControl() throws Exception {
        final var reservedUser = "rename_reserved_" + randomAsciiAlphanumOfLength(8);
        final var regularUser = "rename_regular_" + randomAsciiAlphanumOfLength(8);
        final var reservedMapping = "rename_reserved_role_" + randomAsciiAlphanumOfLength(8);
        try (TestRestClient superAdmin = localCluster.getAdminCertRestClient()) {
            assertThat(
                superAdmin.putJson(apiPath(reservedUser), internalUser(null, true, randomAsciiAlphanumOfLength(12), null, null, null)),
                isCreated()
            );
            assertThat(superAdmin.putJson(apiPath(regularUser), internalUserWithPassword(randomAsciiAlphanumOfLength(12))), isCreated());
            assertThat(
                superAdmin.putJson(
                    securityApi("roles", reservedMapping),
                    (builder, params) -> builder.startObject().field("description", "rename test").endObject()
                ),
                isCreated()
            );
            assertThat(
                superAdmin.putJson(
                    securityApi("rolesmapping", reservedMapping),
                    (builder, params) -> builder.startObject().array("users", regularUser).field("reserved", true).endObject()
                ),
                isCreated()
            );
        }

        // No REST API access at all.
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.postJson(renamePath(regularUser), renameBody("x")), isForbidden());
        }
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Reserved users can't be renamed without REST admin rights.
            assertThat(client.postJson(renamePath(reservedUser), renameBody(reservedUser + "_2")), isForbidden());
            // Nor can a regular user whose name appears in a reserved role mapping: the rename would edit that mapping.
            assertThat(client.postJson(renamePath(regularUser), renameBody(regularUser + "_2")), isForbidden());
            assertThat(client.get(apiPath(regularUser)), isOk());
            assertThat(mappedUsers(client, reservedMapping), is(List.of(regularUser)));
        }
        // The super-admin can do both.
        try (TestRestClient superAdmin = localCluster.getAdminCertRestClient()) {
            assertThat(superAdmin.postJson(renamePath(reservedUser), renameBody(reservedUser + "_2")), isOk());
            assertThat(superAdmin.postJson(renamePath(regularUser), renameBody(regularUser + "_2")), isOk());
            assertThat(mappedUsers(superAdmin, reservedMapping), is(List.of(regularUser + "_2")));
        }
    }

    @Test
    public void renameMergesExistingReferenceToNewName() throws Exception {
        // A role mapping can already list the new name, for example left over from a deleted user. The renamed user
        // inherits that mapping, and the mapping ends up with a single entry for the new name.
        final var oldName = "rename_src_" + randomAsciiAlphanumOfLength(8);
        final var newName = "rename_dst_" + randomAsciiAlphanumOfLength(8);
        final var otherUser = "rename_other_" + randomAsciiAlphanumOfLength(8);
        final var role = "rename_role_" + randomAsciiAlphanumOfLength(8);
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.putJson(apiPath(oldName), internalUserWithPassword(randomAsciiAlphanumOfLength(12))), isCreated());
            createRoleMappedToUsers(client, role, oldName, otherUser, newName);

            final var response = client.postJson(renamePath(oldName), renameBody(newName));
            assertThat(response, isOk());
            assertThat(response.getTextFromJsonBody("/updated_roles_mapping/0"), is(role));
            assertThat(mappedUsers(client, role), is(List.of(newName, otherUser)));
        }
    }

    @Test
    public void parallelRenamesOfSameUserLeaveConsistentState() throws Exception {
        final var source = "rename_src_" + randomAsciiAlphanumOfLength(8);
        final var role = "rename_role_" + randomAsciiAlphanumOfLength(8);
        final var targets = new ArrayList<String>();
        for (int i = 0; i < 10; i++) {
            targets.add(source + "_" + i);
        }
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            assertThat(client.putJson(apiPath(source), internalUserWithPassword(randomAsciiAlphanumOfLength(12))), isCreated());
            createRoleMappedToUsers(client, role, source);

            final var responses = new ArrayList<HttpResponse>();
            try (final var executorService = Executors.newFixedThreadPool(targets.size())) {
                final var futures = new ArrayList<Future<HttpResponse>>();
                for (final var target : targets) {
                    futures.add(executorService.submit(() -> client.postJson(renamePath(source), renameBody(target))));
                }
                for (final var future : futures) {
                    responses.add(future.get());
                }
            }

            // Exactly one rename wins. The rest either lost the _seq_no race (409) or arrived after the
            // source was gone (404). None may succeed partially.
            final var winners = new ArrayList<String>();
            for (int i = 0; i < responses.size(); i++) {
                final int status = responses.get(i).getStatusCode();
                if (status == HttpStatus.SC_OK) {
                    winners.add(targets.get(i));
                } else {
                    assertThat(status == HttpStatus.SC_CONFLICT || status == HttpStatus.SC_NOT_FOUND, is(true));
                }
            }
            assertThat(winners.size(), is(1));
            final var winner = winners.get(0);

            // Both documents agree on the winner.
            assertThat(client.get(apiPath(source)), isNotFound());
            for (final var target : targets) {
                assertThat(
                    client.get(apiPath(target)).getStatusCode(),
                    is(target.equals(winner) ? HttpStatus.SC_OK : HttpStatus.SC_NOT_FOUND)
                );
            }
            assertThat(mappedUsers(client, role), is(List.of(winner)));
        }
    }

    private String randomAsciiAlphanumOfLength(int length) {
        final var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        final var random = new Random();
        final var sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            final var randomIndex = random.nextInt(characters.length());
            sb.append(characters.charAt(randomIndex));
        }
        return sb.toString();
    }
}
