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

import java.io.IOException;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Test;

import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.security.util.FakeRestRequest;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RolesApiActionRequestContentValidatorTest extends AbstractApiActionValidationTest {

    @Test
    public void doesNotValidateMaskedFields() throws IOException {

        final var requestContentValidator = new RolesApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator()
            .createRequestContentValidator();

        // no masked fields
        final var noMaskedFields = objectMapper.createObjectNode()
            .set(
                "index_permissions",
                objectMapper.createArrayNode()
                    .add(
                        objectMapper.createObjectNode()
                            .<ObjectNode>set("index_patterns", objectMapper.createArrayNode().add("a*"))
                            .put("dls", "")
                            .<ObjectNode>set("fls", objectMapper.createArrayNode())
                            .set("allowed_actions", objectMapper.createArrayNode().add("read"))
                    )
                    .add(
                        objectMapper.createObjectNode()
                            .<ObjectNode>set("index_patterns", objectMapper.createArrayNode().add("b*"))
                            .put("dls", "")
                            .<ObjectNode>set("fls", objectMapper.createArrayNode())
                            .set("allowed_actions", objectMapper.createArrayNode().add("write"))
                    )
                    .add(
                        objectMapper.createObjectNode()
                            .<ObjectNode>set("index_patterns", objectMapper.createArrayNode().add("c*"))
                            .put("dls", "")
                            .<ObjectNode>set("fls", objectMapper.createArrayNode())
                            .set("allowed_actions", objectMapper.createArrayNode().add("read").add("write"))

                    )
            );

        var result = requestContentValidator.validate(
            FakeRestRequest.builder().withContent(new BytesArray(noMaskedFields.toString())).build()
        );
        assertTrue(result.isValid());
        result = requestContentValidator.validate(
            FakeRestRequest.builder().withContent(new BytesArray(noMaskedFields.toString())).build(),
            noMaskedFields
        );
        assertTrue(result.isValid());
    }

    @Test
    public void validateOnlySpecifiedMaskedFields() throws IOException {
        final var requestContentValidator = new RolesApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator()
            .createRequestContentValidator();
        final var specifiedMaskedFields = objectMapper.createObjectNode()
            .set(
                "index_permissions",
                objectMapper.createArrayNode()
                    .add(
                        objectMapper.createObjectNode()
                            .<ObjectNode>set("index_patterns", objectMapper.createArrayNode().add("a*"))
                            .put("dls", "")
                            .<ObjectNode>set("fls", objectMapper.createArrayNode())
                            .<ObjectNode>set("masked_fields", objectMapper.nullNode())
                            .set("allowed_actions", objectMapper.createArrayNode().add("read"))
                    )
                    .add(
                        objectMapper.createObjectNode()
                            .<ObjectNode>set("index_patterns", objectMapper.createArrayNode().add("b*"))
                            .put("dls", "")
                            .<ObjectNode>set("fls", objectMapper.createArrayNode())
                            .set("allowed_actions", objectMapper.createArrayNode().add("write"))
                    )
                    .add(
                        objectMapper.createObjectNode()
                            .<ObjectNode>set("index_patterns", objectMapper.createArrayNode().add("c*"))
                            .put("dls", "")
                            .<ObjectNode>set("fls", objectMapper.createArrayNode())
                            .<ObjectNode>set("masked_fields", objectMapper.createArrayNode().add("aaa::").add("bbb"))
                            .set("allowed_actions", objectMapper.createArrayNode().add("read").add("write"))

                    )
            );
        var result = requestContentValidator.validate(
            FakeRestRequest.builder().withContent(new BytesArray(specifiedMaskedFields.toString())).build()
        );
        assertFalse(result.isValid());
        var errorMessage = xContentToJsonNode(result.errorMessage());
        assertTrue(errorMessage.toString(), errorMessage.toString().contains("aaa::"));

        result = requestContentValidator.validate(
            FakeRestRequest.builder().withContent(new BytesArray(specifiedMaskedFields.toString())).build(),
            specifiedMaskedFields
        );
        assertFalse(result.isValid());
        errorMessage = xContentToJsonNode(result.errorMessage());
        assertTrue(errorMessage.toString(), errorMessage.toString().contains("aaa::"));
    }

    @Test
    public void validateAllMaskedFields() throws IOException {
        final var requestContentValidator = new RolesApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator()
            .createRequestContentValidator();
        final var invalidMaskedFields = objectMapper.createObjectNode()
            .set(
                "index_permissions",
                objectMapper.createArrayNode()
                    .add(
                        objectMapper.createObjectNode()
                            .<ObjectNode>set("index_patterns", objectMapper.createArrayNode().add("a*"))
                            .put("dls", "")
                            .<ObjectNode>set("fls", objectMapper.createArrayNode())
                            .<ObjectNode>set("masked_fields", objectMapper.createArrayNode().add("aaa").add("bbb"))
                            .set("allowed_actions", objectMapper.createArrayNode().add("read"))
                    )
                    .add(
                        objectMapper.createObjectNode()
                            .<ObjectNode>set("index_patterns", objectMapper.createArrayNode().add("b*"))
                            .put("dls", "")
                            .<ObjectNode>set("fls", objectMapper.createArrayNode())
                            .<ObjectNode>set("masked_fields", objectMapper.createArrayNode().add("aaa::").add("bbb::").add("ccc:::"))
                            .set("allowed_actions", objectMapper.createArrayNode().add("write"))
                    )
                    .add(
                        objectMapper.createObjectNode()
                            .<ObjectNode>set("index_patterns", objectMapper.createArrayNode().add("c*"))
                            .put("dls", "")
                            .<ObjectNode>set("fls", objectMapper.createArrayNode())
                            .<ObjectNode>set("masked_fields", objectMapper.createArrayNode().add("ddd::").add("eee"))
                            .set("allowed_actions", objectMapper.createArrayNode().add("read").add("write"))

                    )
            );
        var result = requestContentValidator.validate(
            FakeRestRequest.builder().withContent(new BytesArray(invalidMaskedFields.toString())).build()
        );
        assertFalse(result.isValid());
        var errorMessage = xContentToJsonNode(result.errorMessage()).toString();
        assertTrue(errorMessage, errorMessage.contains("aaa::"));
        assertTrue(errorMessage, errorMessage.contains("bbb::"));
        assertTrue(errorMessage, errorMessage.contains("ccc:::"));
        assertTrue(errorMessage, errorMessage.contains("ddd::"));

        result = requestContentValidator.validate(
            FakeRestRequest.builder().withContent(new BytesArray(invalidMaskedFields.toString())).build(),
            invalidMaskedFields
        );
        assertFalse(result.isValid());
        errorMessage = xContentToJsonNode(result.errorMessage()).toString();
        assertTrue(errorMessage, errorMessage.contains("aaa::"));
        assertTrue(errorMessage, errorMessage.contains("bbb::"));
        assertTrue(errorMessage, errorMessage.contains("ccc:::"));
        assertTrue(errorMessage, errorMessage.contains("ddd::"));
    }
}
