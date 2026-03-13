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

import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

import org.hamcrest.Matcher;

import org.opensearch.common.CheckedSupplier;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import com.nimbusds.jose.util.Pair;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.oneOf;
import static org.opensearch.security.api.PatchPayloadHelper.addOp;
import static org.opensearch.security.api.PatchPayloadHelper.patch;
import static org.opensearch.security.api.PatchPayloadHelper.removeOp;
import static org.opensearch.security.api.PatchPayloadHelper.replaceOp;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public abstract class AbstractConfigEntityApiIntegrationTest extends AbstractApiIntegrationTest {

    protected static LocalCluster.Builder clusterBuilder() {
        return AbstractApiIntegrationTest.clusterBuilder().nodeSetting(SECURITY_RESTAPI_ADMIN_ENABLED, true);
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

    public void forbiddenForRegularUsers(LocalCluster localCluster) throws Exception {
        try (TestRestClient client = localCluster.getRestClient(NEW_USER)) {
            assertThat(client.putJson(apiPath("some_entity"), EMPTY_BODY), isForbidden());
            assertThat(client.get(apiPath()), isForbidden());
            assertThat(client.get(apiPath("some_entity")), isForbidden());
            assertThat(client.putJson(apiPath("some_entity"), EMPTY_BODY), isForbidden());
            assertThat(client.patch(apiPath(), EMPTY_BODY), isForbidden());
            assertThat(client.patch(apiPath("some_entity"), EMPTY_BODY), isForbidden());
            assertThat(client.delete(apiPath("some_entity")), isForbidden());
        }
    }

    public void availableForAdminUser(LocalCluster localCluster) throws Exception {
        final var entitiesNames = predefinedHiddenAndReservedConfigEntities(localCluster);
        final var hiddenEntityName = entitiesNames.getLeft();
        final var reservedEntityName = entitiesNames.getRight();
        // can't see hidden resources
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            verifyNoHiddenEntities(() -> client.get(apiPath()));
            creationOfReadOnlyEntityForbidden(
                "str1234567",
                client,
                (builder, params) -> testDescriptor.hiddenEntityPayload().toXContent(builder, params),
                (builder, params) -> testDescriptor.reservedEntityPayload().toXContent(builder, params),
                (builder, params) -> testDescriptor.staticEntityPayload().toXContent(builder, params)
            );
            verifyUpdateAndDeleteHiddenConfigEntityForbidden(hiddenEntityName, client);
            verifyUpdateAndDeleteReservedConfigEntityForbidden(reservedEntityName, client);
            verifyCrudOperations(null, null, client);
            verifyBadRequestOperations(client);
        }
    }

    Pair<String, String> predefinedHiddenAndReservedConfigEntities(LocalCluster localCluster) throws Exception {
        final var hiddenEntityName = "str_hidden";
        final var reservedEntityName = "str_reserved";
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            assertThat(client.putJson(apiPath(hiddenEntityName), testDescriptor.hiddenEntityPayload()), isCreated());
            assertThat(client.putJson(apiPath(reservedEntityName), testDescriptor.reservedEntityPayload()), isCreated());
        }
        return Pair.of(hiddenEntityName, reservedEntityName);
    }

    public void availableForTLSAdminUser(LocalCluster localCluster) throws Exception {
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            availableForSuperAdminUser(client);
        }
    }

    public void availableForRESTAdminUser(LocalCluster localCluster) throws Exception {
        try (TestRestClient client = localCluster.getRestClient(REST_ADMIN_USER)) {
            availableForSuperAdminUser(client);
        }
    }

    void availableForSuperAdminUser(final TestRestClient client) throws Exception {
        creationOfReadOnlyEntityForbidden(
            randomAlphanumericString(),
            client,
            (builder, params) -> testDescriptor.staticEntityPayload().toXContent(builder, params)
        );
        verifyCrudOperations(true, null, client);
        verifyCrudOperations(null, true, client);
        verifyCrudOperations(null, null, client);
        verifyBadRequestOperations(client);
        forbiddenToCreateEntityWithRestAdminPermissions(client);
        forbiddenToUpdateAndDeleteExistingEntityWithRestAdminPermissions(client);
    }

    protected String randomAlphanumericString() {
        return "str_" + java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 10);
    }

    void verifyNoHiddenEntities(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback) throws Exception {
        final var resp = endpointCallback.get();
        assertThat(resp, isOk());
        final var body = resp.bodyAsJsonNode();
        final var pretty = body.toPrettyString();
        final var it = body.elements();
        while (it.hasNext()) {
            final var e = it.next();
            assertThat(pretty, not(e.get("hidden").asBoolean()));
        }
    }

    void creationOfReadOnlyEntityForbidden(final String entityName, final TestRestClient client, final ToXContentObject... entities)
        throws Exception {
        for (final var configEntity : entities) {
            final var resp = client.putJson(apiPath(entityName), configEntity);
            assertThat(resp, isBadRequest());
            assertInvalidKeys(resp, is(oneOf("static", "hidden", "reserved")));
            final var resp2 = client.patch(apiPath(), patch(addOp("str1234567", configEntity)));
            assertThat(resp2, isBadRequest());
        }
    }

    void assertNullValuesInArray(final TestRestClient.HttpResponse response) throws Exception {
        assertThat(
            response.getBody(),
            response.getTextFromJsonBody("/reason"),
            equalTo("`null` or blank values are not allowed as json array elements")
        );
    }

    void assertInvalidKeys(final TestRestClient.HttpResponse response, final String expectedInvalidKeys) {
        assertInvalidKeys(response, equalTo(expectedInvalidKeys));
    }

    void assertInvalidKeys(final TestRestClient.HttpResponse response, final Matcher<String> expectedInvalidKeysMatcher) {
        assertThat(response.getBody(), response.getTextFromJsonBody("/status"), is("error"));
        assertThat(response.getBody(), response.getTextFromJsonBody("/reason"), equalTo("Invalid configuration"));
        assertThat(response.getBody(), response.getTextFromJsonBody("/invalid_keys/keys"), expectedInvalidKeysMatcher);
    }

    void assertWrongDataType(final TestRestClient.HttpResponse response, final Map<String, String> expectedMessages) {
        assertThat(response.getBody(), response.getTextFromJsonBody("/status"), is("error"));
        for (final var p : expectedMessages.entrySet())
            assertThat(response.getBody(), response.getTextFromJsonBody("/" + p.getKey()), is(p.getValue()));
    }

    void verifyUpdateAndDeleteHiddenConfigEntityForbidden(final String hiddenEntityName, final TestRestClient client) throws Exception {
        final var expectedErrorMessage = "Resource '" + hiddenEntityName + "' is not available.";
        assertThat(
            client.putJson(apiPath(hiddenEntityName), testDescriptor.entityPayload()),
            isNotFound().withAttribute("/message", expectedErrorMessage)
        );
        assertThat(
            client.patch(
                apiPath(hiddenEntityName),
                patch(replaceOp(testDescriptor.entityJsonProperty(), testDescriptor.jsonPropertyPayload()))
            ),
            isNotFound().withAttribute("/message", expectedErrorMessage)
        );
        assertThat(
            client.patch(apiPath(), patch(replaceOp(hiddenEntityName, testDescriptor.entityPayload()))),
            isNotFound().withAttribute("/message", expectedErrorMessage)
        );
        assertThat(
            client.patch(apiPath(hiddenEntityName), patch(removeOp(testDescriptor.entityJsonProperty()))),
            isNotFound().withAttribute("/message", expectedErrorMessage)
        );
        assertThat(
            client.patch(apiPath(), patch(removeOp(hiddenEntityName))),
            isNotFound().withAttribute("/message", expectedErrorMessage)
        );
        assertThat(client.delete(apiPath(hiddenEntityName)), isNotFound().withAttribute("/message", expectedErrorMessage));
    }

    void verifyUpdateAndDeleteReservedConfigEntityForbidden(final String reservedEntityName, final TestRestClient client) throws Exception {
        final var expectedErrorMessage = "Resource '" + reservedEntityName + "' is reserved.";
        assertThat(
            client.putJson(apiPath(reservedEntityName), testDescriptor.entityPayload()),
            isForbidden().withAttribute("/message", expectedErrorMessage)
        );
        assertThat(
            client.patch(
                apiPath(reservedEntityName),
                patch(replaceOp(testDescriptor.entityJsonProperty(), testDescriptor.entityJsonProperty()))
            ),
            isForbidden().withAttribute("/message", expectedErrorMessage)
        );
        assertThat(
            client.patch(apiPath(), patch(replaceOp(reservedEntityName, testDescriptor.entityPayload()))),
            isForbidden().withAttribute("/message", expectedErrorMessage)
        );
        assertThat(
            client.patch(apiPath(), patch(removeOp(reservedEntityName))),
            isForbidden().withAttribute("/message", expectedErrorMessage)
        );
        assertThat(
            client.patch(apiPath(reservedEntityName), patch(removeOp(testDescriptor.entityJsonProperty()))),
            isForbidden().withAttribute("/message", expectedErrorMessage)
        );
        assertThat(client.delete(apiPath(reservedEntityName)), isForbidden().withAttribute("/message", expectedErrorMessage));
    }

    void forbiddenToCreateEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {}

    void forbiddenToUpdateAndDeleteExistingEntityWithRestAdminPermissions(final TestRestClient client) throws Exception {}

    abstract void verifyBadRequestOperations(final TestRestClient client) throws Exception;

    abstract void verifyCrudOperations(final Boolean hidden, final Boolean reserved, final TestRestClient client) throws Exception;
}
