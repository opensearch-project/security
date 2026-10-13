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

package org.opensearch.security.tools;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.support.ConfigHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

/**
 * Tests for the conversion used by {@code securityadmin -backup}, see
 * https://github.com/opensearch-project/security/issues/6572.
 */
public class SecurityAdminConvertToYamlTest {

    private static final String ACTION_GROUPS_JSON = "{\"_meta\":{\"type\":\"actiongroups\",\"config_version\":2},"
        + "\"my_group\":{\"reserved\":false,\"allowed_actions\":[\"indices:data/read/*\"]}}";

    /**
     * Documents in the security index store their configuration base64 encoded under a field named after the
     * document id. The backup must contain the decoded configuration, in a form that passes the same validation
     * securityadmin applies before writing the file.
     */
    @Test
    public void decodesBase64EncodedDocument() throws Exception {
        Map<String, Object> document = Map.of("actiongroups", encode(ACTION_GROUPS_JSON));

        String yaml = SecurityAdmin.convertToYaml("actiongroups", document, true);

        SecurityDynamicConfiguration<ActionGroupsV7> config = ConfigHelper.fromYamlString(yaml, CType.ACTIONGROUPS, 2, 0, 0);
        assertThat(config.getCEntry("my_group").getAllowed_actions(), equalTo(List.of("indices:data/read/*")));
    }

    @Test
    public void returnsNullWhenDocumentHasNoFieldForType() throws Exception {
        Map<String, Object> document = Map.of("roles", encode(ACTION_GROUPS_JSON));

        assertThat(SecurityAdmin.convertToYaml("actiongroups", document, true), nullValue());
    }

    @Test
    public void returnsNullWhenValueIsNotEncoded() throws Exception {
        Map<String, Object> document = Map.of("actiongroups", Map.of("my_group", Map.of("reserved", false)));

        assertThat(SecurityAdmin.convertToYaml("actiongroups", document, true), nullValue());
    }

    private static String encode(String json) {
        return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
