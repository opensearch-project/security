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

package org.opensearch.security.dlic.rest.api;

import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Test;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.util.FakeRestRequest;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

public class AuthFailureListenersApiActionValidationTest extends AbstractApiActionValidationTest {

    @Test
    public void validateAllowedFields() throws IOException {
        final var authFailureListenerApiActionRequestContentValidator = new AuthFailureListenersApiAction(clusterService, threadPool, securityApiDependencies)
                .createEndpointValidator()
                .createRequestContentValidator();

        final var authFailureListener = new ConfigV7.AuthFailureListener();

        final var content = DefaultObjectMapper.writeValueAsString(objectMapper.valueToTree(authFailureListener), false);

        var validResult = authFailureListenerApiActionRequestContentValidator.validate( FakeRestRequest.builder()
                .withMethod(RestRequest.Method.PUT)
                .withPath("_plugins/_security/api/authfailurelisteners/test")
                .withContent(new BytesArray(content))
                .build());
        assertTrue(validResult.isValid());

        final var invalidContent = objectMapper.createObjectNode()
                .set(
                        "blah",
                        objectMapper.createObjectNode()

                );


        var inValidResult = authFailureListenerApiActionRequestContentValidator.validate( FakeRestRequest.builder()
                .withMethod(RestRequest.Method.PUT)
                .withPath("_plugins/_security/api/authfailurelisteners/test")
                .withContent(new BytesArray(invalidContent.toString()))
                .build());
        assertFalse(inValidResult.isValid());
        assertThat(inValidResult.status(), is(RestStatus.BAD_REQUEST));
    }
}
