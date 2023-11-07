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

import org.junit.Test;

import org.opensearch.core.rest.RestStatus;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class NodesDnApiActionValidationTest extends AbstractApiActionValidationTest {

    @Test
    public void isNotAllowedToChangeImmutableEntity() throws Exception {

        final var nodesDnApiActionEndpointValidator = new NodesDnApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator();

        final var result = nodesDnApiActionEndpointValidator.isAllowedToChangeImmutableEntity(
            SecurityConfiguration.of(NodesDnApiAction.STATIC_OPENSEARCH_YML_NODES_DN, configuration)
        );

        assertFalse(result.isValid());
        assertEquals(RestStatus.FORBIDDEN, result.status());
    }

}
