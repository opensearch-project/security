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

import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.removeOp;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class TenantsRestApiIntegrationTest extends AbstractConfigEntityApiIntegrationTest {

    private final static String REST_API_ADMIN_TENANTS_ONLY = "rest_api_admin_tenants_only";

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().users(
        new TestSecurityConfig.User(REST_API_ADMIN_TENANTS_ONLY).roles(
            REST_ADMIN_REST_API_ACCESS_ROLE,
            new TestSecurityConfig.Role("rest_admin_role").clusterPermissions(restAdminPermission(Endpoint.TENANTS))
        )
    ).build();

    public TenantsRestApiIntegrationTest() {
        super("tenants", new TestDescriptor() {
            @Override
            public String entityJsonProperty() {
                return "description";
            }

            @Override
            public ToXContentObject entityPayload(Boolean hidden, Boolean reserved, Boolean _static) {
                return tenant(hidden, reserved, _static);
            }

            @Override
            public ToXContentObject jsonPropertyPayload() {
                return (builder, params) -> builder.value(randomAsciiAlphanumOfLength(10));
            }

            @Override
            public Optional<String> restAdminLimitedUser() {
                return Optional.of(REST_API_ADMIN_TENANTS_ONLY);
            }
        });
    }

    static ToXContentObject tenant(final Boolean hidden, final Boolean reserved, final String description) {
        return tenant(hidden, reserved, null, description);
    }

    static ToXContentObject tenant(final Boolean hidden, final Boolean reserved, final Boolean _static) {
        return tenant(hidden, reserved, _static, randomAsciiAlphanumOfLength(10));
    }

    static ToXContentObject tenant(final Boolean hidden, final Boolean reserved, final Boolean _static, String description) {
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
            builder.field("description", description);
            return builder.endObject();
        };
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
    void verifyBadRequestOperations(TestRestClient client) throws Exception {
        // put
        assertThat(client.putJson(apiPath(randomAsciiAlphanumOfLength(4)), EMPTY_BODY), isBadRequest());
        assertThat(
            client.putJson(
                apiPath(randomAsciiAlphanumOfLength(4)),
                (builder, params) -> builder.startObject().field("description", "a").field("description", "b").endObject()
            ),
            isBadRequest()
        );
        assertInvalidKeys(
            client.putJson(
                apiPath(randomAsciiAlphanumOfLength(10)),
                (builder, params) -> builder.startObject().field("a", "b").field("c", "d").field("description", "e").endObject()
            ),
            "a,c"
        );
        // patch
        assertThat(client.patch(apiPath(), EMPTY_BODY), isBadRequest());
        assertThat(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        randomAsciiAlphanumOfLength(4),
                        (ToXContentObject) (builder, params) -> builder.startObject()
                            .field("description", "a")
                            .field("description", "b")
                            .endObject()
                    )
                )
            ),
            isBadRequest()
        );
        assertInvalidKeys(
            client.patch(
                apiPath(),
                patch(
                    addOp(
                        randomAsciiAlphanumOfLength(10),
                        (ToXContentObject) (builder, params) -> builder.startObject()
                            .field("a", "b")
                            .field("c", "d")
                            .field("description", "e")
                            .endObject()
                    )
                )
            ),
            "a,c"
        );

    }

    @Override
    void verifyCrudOperations(Boolean hidden, Boolean reserved, TestRestClient client) throws Exception {
        // put
        final var putDescription = randomAsciiAlphanumOfLength(10);
        final var putTenantName = randomAsciiAlphanumOfLength(4);
        assertThat(client.putJson(apiPath(putTenantName), tenant(hidden, reserved, putDescription)), isCreated());
        assertTenant(client.get(apiPath(putTenantName)).bodyAsJsonNode().get(putTenantName), hidden, reserved, putDescription);

        final var putUpdatedDescription = randomAsciiAlphanumOfLength(10);
        assertThat(client.putJson(apiPath(putTenantName), tenant(hidden, reserved, putUpdatedDescription)), isOk());
        assertTenant(
            ok(() -> client.get(apiPath(putTenantName))).bodyAsJsonNode().get(putTenantName),
            hidden,
            reserved,
            putUpdatedDescription
        );
        assertThat(client.delete(apiPath(putTenantName)), isOk());
        assertThat(client.get(apiPath(putTenantName)), isNotFound());
        // patch
        final var patchTenantName = randomAsciiAlphanumOfLength(4);
        final var patchDescription = randomAsciiAlphanumOfLength(10);
        assertThat(client.patch(apiPath(), patch(addOp(patchTenantName, tenant(hidden, reserved, patchDescription)))), isOk());
        assertTenant(
            ok(() -> client.get(apiPath(patchTenantName))).bodyAsJsonNode().get(patchTenantName),
            hidden,
            reserved,
            patchDescription
        );

        final var patchUpdatedDescription = randomAsciiAlphanumOfLength(10);
        assertThat(client.patch(apiPath(patchTenantName), patch(replaceOp("description", patchUpdatedDescription))), isOk());
        assertTenant(
            ok(() -> client.get(apiPath(patchTenantName))).bodyAsJsonNode().get(patchTenantName),
            hidden,
            reserved,
            patchUpdatedDescription
        );

        assertThat(client.patch(apiPath(), patch(removeOp(patchTenantName))), isOk());
        assertThat(client.get(apiPath(patchTenantName)), isNotFound());
    }

    void assertTenant(final JsonNode actualJson, final Boolean hidden, final Boolean reserved, final String expectedDescription) {
        assertThat(actualJson.toPrettyString(), actualJson.get("hidden").asBoolean(), is(hidden != null && hidden));
        assertThat(actualJson.toPrettyString(), actualJson.get("reserved").asBoolean(), is(reserved != null && reserved));
        assertThat(actualJson.toPrettyString(), actualJson.get("description").asText(), is(expectedDescription));
    }

}
