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
import java.util.StringJoiner;

import org.hamcrest.Matcher;
import org.junit.Test;

import org.opensearch.common.CheckedSupplier;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.oneOf;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.removeOp;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public abstract class AbstractConfigEntityApiIntegrationTest extends AbstractApiIntegrationTest {

    static {
        clusterSettings.put(SECURITY_RESTAPI_ADMIN_ENABLED, true);
        testSecurityConfig.withRestAdminUser(REST_ADMIN_USER, allRestAdminPermissions());
    }

    interface TestDescriptor {

        String entityJsonProperty();

        default ToXContentObject entityPayload() {
            return entityPayload(null, null, null);
        }

        default ToXContentObject reservedEntityPayload() {
            return entityPayload(null, true, null);
        }

        default ToXContentObject hiddenEntityPayload() {
            return entityPayload(true, null, null);
        }

        default ToXContentObject staticEntityPayload() {
            return entityPayload(null, null, true);
        }

        ToXContentObject entityPayload(final Boolean hidden, final Boolean reserved, final Boolean _static);

        ToXContentObject jsonPropertyPayload();

        default Optional<String> restAdminLimitedUser() {
            return Optional.empty();
        }

    }

    private final String path;

    private final TestDescriptor testDescriptor;

    public AbstractConfigEntityApiIntegrationTest(final String path, final TestDescriptor testDescriptor) {
        this.path = path;
        this.testDescriptor = testDescriptor;
    }

    @Override
    protected String apiPath(String... paths) {
        final StringJoiner fullPath = new StringJoiner("/").add(super.apiPath(path));
        if (paths != null) {
            for (final var p : paths) {
                fullPath.add(p);
            }
        }
        return fullPath.toString();
    }

    @Test
    public void forbiddenForRegularUsers() throws Exception {
        withUser(NEW_USER, client -> {
            forbidden(() -> client.putJson(apiPath("some_entity"), EMPTY_BODY));
            forbidden(() -> client.get(apiPath()));
            forbidden(() -> client.get(apiPath("some_entity")));
            forbidden(() -> client.putJson(apiPath("some_entity"), EMPTY_BODY));
            forbidden(() -> client.patch(apiPath(), EMPTY_BODY));
            forbidden(() -> client.patch(apiPath("some_entity"), EMPTY_BODY));
            forbidden(() -> client.delete(apiPath("some_entity")));
        });
    }

    @Test
    public void availableForAdminUser() throws Exception {
        final var hiddenEntityName = randomAsciiAlphanumOfLength(10);
        final var reservedEntityName = randomAsciiAlphanumOfLength(10);
        withUser(
            ADMIN_USER_NAME,
            localCluster.getAdminCertificate(),
            client -> created(() -> client.putJson(apiPath(hiddenEntityName), testDescriptor.hiddenEntityPayload()))
        );
        withUser(
            ADMIN_USER_NAME,
            localCluster.getAdminCertificate(),
            client -> created(() -> client.putJson(apiPath(reservedEntityName), testDescriptor.reservedEntityPayload()))
        );

        // can't see hidden resources
        withUser(ADMIN_USER_NAME, client -> {
            verifyNoHiddenEntities(() -> client.get(apiPath()));
            creationOfReadOnlyEntityForbidden(
                client,
                (builder, params) -> testDescriptor.hiddenEntityPayload().toXContent(builder, params),
                (builder, params) -> testDescriptor.reservedEntityPayload().toXContent(builder, params),
                (builder, params) -> testDescriptor.staticEntityPayload().toXContent(builder, params)
            );
            verifyUpdateAndDeleteHiddenConfigEntityForbidden(hiddenEntityName, client);
            verifyUpdateAndDeleteReservedConfigEntityForbidden(reservedEntityName, client);
            verifyCrudOperations(null, null, client);
            verifyBadRequestOperations(client);
        });
    }

    @Test
    public void availableForTLSAdminUser() throws Exception {
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), this::availableForSuperAdminUser);
    }

    @Test
    public void availableForRESTAdminUser() throws Exception {
        withUser(REST_ADMIN_USER, this::availableForSuperAdminUser);
        if (testDescriptor.restAdminLimitedUser().isPresent()) {
            withUser(testDescriptor.restAdminLimitedUser().get(), this::availableForSuperAdminUser);
        }
    }

    void availableForSuperAdminUser(final TestRestClient client) throws Exception {
        creationOfReadOnlyEntityForbidden(client, (builder, params) -> testDescriptor.staticEntityPayload().toXContent(builder, params));
        verifyCrudOperations(true, null, client);
        verifyCrudOperations(null, true, client);
        verifyCrudOperations(null, null, client);
        verifyBadRequestOperations(client);
        forbiddenToCreateEntityWithRestAdminPermissions(client);
        forbiddenToUpdateAndDeleteExistingEntityWithRestAdminPermissions(client);
    }

    void verifyNoHiddenEntities(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback) throws Exception {
        final var body = ok(endpointCallback).bodyAsJsonNode();
        final var pretty = body.toPrettyString();
        final var it = body.elements();
        while (it.hasNext()) {
            final var e = it.next();
            assertThat(pretty, not(e.get("hidden").asBoolean()));
        }
    }

    void creationOfReadOnlyEntityForbidden(final TestRestClient client, final ToXContentObject... entities) throws Exception {
        for (final var configEntity : entities) {
            assertInvalidKeys(
                badRequest(() -> client.putJson(apiPath(randomAsciiAlphanumOfLength(10)), configEntity)),
                is(oneOf("static", "hidden", "reserved"))
            );
            badRequest(() -> client.patch(apiPath(), patch(addOp(randomAsciiAlphanumOfLength(10), configEntity))));
        }
    }

    void assertNullValuesInArray(final TestRestClient.HttpResponse response) throws Exception {
        assertThat(response.getBody(), response.getTextFromJsonBody("/reason"), equalTo("`null` is not allowed as json array element"));
    }

    void assertInvalidKeys(final TestRestClient.HttpResponse response, final String expectedInvalidKeys) {
        assertInvalidKeys(response, equalTo(expectedInvalidKeys));
    }

    void assertInvalidKeys(final TestRestClient.HttpResponse response, final Matcher<String> expectedInvalidKeysMatcher) {
        assertThat(response.getBody(), response.getTextFromJsonBody("/status"), is("error"));
        assertThat(response.getBody(), response.getTextFromJsonBody("/reason"), equalTo("Invalid configuration"));
        assertThat(response.getBody(), response.getTextFromJsonBody("/invalid_keys/keys"), expectedInvalidKeysMatcher);
    }

    void assertSpecifyOneOf(final TestRestClient.HttpResponse response, final String expectedSpecifyOneOfKeys) {
        assertThat(response.getBody(), response.getTextFromJsonBody("/status"), is("error"));
        assertThat(response.getBody(), response.getTextFromJsonBody("/reason"), equalTo("Invalid configuration"));
        assertThat(response.getBody(), response.getTextFromJsonBody("/specify_one_of/keys"), containsString(expectedSpecifyOneOfKeys));
    }

    void assertMissingMandatoryKeys(final TestRestClient.HttpResponse response, final String expectedKeys) {
        assertThat(response.getBody(), response.getTextFromJsonBody("/status"), is("error"));
        assertThat(response.getBody(), response.getTextFromJsonBody("/reason"), equalTo("Invalid configuration"));
        assertThat(response.getBody(), response.getTextFromJsonBody("/missing_mandatory_keys/keys"), containsString(expectedKeys));
    }

    void verifyUpdateAndDeleteHiddenConfigEntityForbidden(final String hiddenEntityName, final TestRestClient client) throws Exception {
        final var expectedErrorMessage = "Resource '" + hiddenEntityName + "' is not available.";
        notFound(() -> client.putJson(apiPath(hiddenEntityName), testDescriptor.entityPayload()), expectedErrorMessage);
        notFound(
            () -> client.patch(
                apiPath(hiddenEntityName),
                patch(replaceOp(testDescriptor.entityJsonProperty(), testDescriptor.jsonPropertyPayload()))
            ),
            expectedErrorMessage
        );
        notFound(() -> client.patch(apiPath(), patch(replaceOp(hiddenEntityName, testDescriptor.entityPayload()))), expectedErrorMessage);
        notFound(() -> client.patch(apiPath(hiddenEntityName), patch(removeOp(testDescriptor.entityJsonProperty()))), expectedErrorMessage);
        notFound(() -> client.patch(apiPath(), patch(removeOp(hiddenEntityName))), expectedErrorMessage);
        notFound(() -> client.delete(apiPath(hiddenEntityName)), expectedErrorMessage);
    }

    void verifyUpdateAndDeleteReservedConfigEntityForbidden(final String reservedEntityName, final TestRestClient client) throws Exception {
        final var expectedErrorMessage = "Resource '" + reservedEntityName + "' is reserved.";
        forbidden(() -> client.putJson(apiPath(reservedEntityName), testDescriptor.entityPayload()), expectedErrorMessage);
        forbidden(
            () -> client.patch(
                apiPath(reservedEntityName),
                patch(replaceOp(testDescriptor.entityJsonProperty(), testDescriptor.entityJsonProperty()))
            ),
            expectedErrorMessage
        );
        forbidden(
            () -> client.patch(apiPath(), patch(replaceOp(reservedEntityName, testDescriptor.entityPayload()))),
            expectedErrorMessage
        );
        forbidden(() -> client.patch(apiPath(), patch(removeOp(reservedEntityName))), expectedErrorMessage);
        forbidden(
            () -> client.patch(apiPath(reservedEntityName), patch(removeOp(testDescriptor.entityJsonProperty()))),
            expectedErrorMessage
        );
        forbidden(() -> client.delete(apiPath(reservedEntityName)), expectedErrorMessage);
    }

    void forbiddenToCreateEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {}

    void forbiddenToUpdateAndDeleteExistingEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {}

    abstract void verifyBadRequestOperations(final TestRestClient client) throws Exception;

    abstract void verifyCrudOperations(final Boolean hidden, final Boolean reserved, final TestRestClient client) throws Exception;
}
