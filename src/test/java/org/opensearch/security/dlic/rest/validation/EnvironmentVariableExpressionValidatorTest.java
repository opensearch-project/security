/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.dlic.rest.validation;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.util.FakeRestRequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class EnvironmentVariableExpressionValidatorTest {
    @Test
    public void rejectsExpressionsInNestedValuesAndKeys() throws Exception {
        for (String expression : List.of(
            "${env.NAME}",
            "${envbc.NAME}",
            "${envbase64.NAME}",
            "${envbase64:NAME}",
            "${env.NAME:-fallback}"
        )) {
            for (Object content : List.of(Map.of("nested", List.of("prefix" + expression + "suffix")), Map.of(expression, "value"))) {
                assertRejected(DefaultObjectMapper.writeValueAsString(content, false), Map.of());
            }
        }
    }

    @Test
    public void rejectsDecodedJsonEscapes() {
        assertRejected("{\"description\":\"\\u0024\\u007benv.NAME}\"}", Map.of());
        assertRejected("{\"\\u0024{env.NAME}\":\"value\"}", Map.of());
    }

    @Test
    public void rejectsDecodedRouteAndQueryParameters() {
        assertRejected("{}", Map.of("name", "${env.NAME}"));
        assertRejected("{}", Map.of("${env.NAME}", "value"));
    }

    @Test
    public void rejectsPatchPathsAndValues() {
        assertRejected("[{\"op\":\"add\",\"path\":\"/${env.NAME}\",\"value\":{}}]", Map.of());
        assertRejected("[{\"op\":\"copy\",\"from\":\"/${env.NAME}\",\"path\":\"/other\"}]", Map.of());
        assertRejected("[{\"op\":\"add\",\"path\":\"/description\",\"value\":\"${env.NAME}\"}]", Map.of());
    }

    @Test
    public void allowsUserTemplatesAndOrdinaryJson() {
        assertTrue(
            validate(RestRequest.Method.PUT, "{\"dls\":\"${user.name} ${attr.internal.team}\",\"n\":null,\"a\":[true,1]}", Map.of())
                .isValid()
        );
        assertTrue(validate(RestRequest.Method.POST, "", Map.of()).isValid());
    }

    @Test
    public void permitsReadsAndDeletesOfExistingNames() {
        for (RestRequest.Method method : List.of(RestRequest.Method.GET, RestRequest.Method.DELETE)) {
            assertTrue(validate(method, "", Map.of("name", "${env.NAME}")).isValid());
        }
    }

    @Test
    public void rejectsMalformedJson() {
        assertEquals(RestStatus.BAD_REQUEST, validate(RestRequest.Method.PUT, "{", Map.of()).status());
    }

    private void assertRejected(String body, Map<String, String> params) {
        for (RestRequest.Method method : List.of(RestRequest.Method.PUT, RestRequest.Method.PATCH, RestRequest.Method.POST)) {
            var result = validate(method, body, params);
            assertFalse(result.isValid());
            assertEquals(RestStatus.BAD_REQUEST, result.status());
        }
    }

    private ValidationResult<RestRequest> validate(RestRequest.Method method, String body, Map<String, String> params) {
        return EnvironmentVariableExpressionValidator.validate(
            FakeRestRequest.builder().withMethod(method).withParams(params).withContent(new BytesArray(body)).build()
        );
    }
}
