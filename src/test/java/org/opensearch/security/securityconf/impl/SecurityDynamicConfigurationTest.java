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

package org.opensearch.security.securityconf.impl;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

public class SecurityDynamicConfigurationTest {

    private SecurityDynamicConfiguration<?> securityDynamicConfiguration;
    private ObjectMapper objectMapper = DefaultObjectMapper.objectMapper;
    private ObjectNode objectNode = objectMapper.createObjectNode();

    @Before
    public void setUp() throws JsonProcessingException, IOException {
        objectNode.set("_meta", objectMapper.createObjectNode().put("type", CType.ROLES.toLCString()).put("config_version", 2));
        securityDynamicConfiguration = SecurityDynamicConfiguration.fromJson(
            objectMapper.writeValueAsString(objectNode),
            CType.ROLES,
            2,
            1,
            1
        );
    }

    @Test
    public void deepClone_shouldReturnNewObject() {
        SecurityDynamicConfiguration<?> securityDeepClone = securityDynamicConfiguration.deepClone();
        assertThat(securityDeepClone, is(not(equalTo(securityDynamicConfiguration))));
    }
}
