/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.tools.SecurityAdmin;

import tools.jackson.databind.JsonNode;

import static org.junit.Assert.assertEquals;

public class SecurityAdminClusterNameTests extends SingleClusterTest {
    @Test
    public void testMismatchDoesNotInitializeSecurityIndex() throws Exception {
        startCluster(false);
        assertEquals(-1, execute("-cn", "wrong-" + clusterInfo.clustername, "-cd", TEST_RESOURCE_ABSOLUTE_PATH));
        assertEquals(404, adminClient().executeGetRequest(".opendistro_security").getStatusCode());

        // Without either option, the expected cluster name is still "opensearch".
        assertEquals(-1, execute("-cd", TEST_RESOURCE_ABSOLUTE_PATH));
        assertEquals(404, adminClient().executeGetRequest(".opendistro_security").getStatusCode());

        assertEquals(0, execute("-cn", clusterInfo.clustername, "-cd", TEST_RESOURCE_ABSOLUTE_PATH));
        assertEquals(200, adminClient().executeGetRequest(".opendistro_security").getStatusCode());
    }

    @Test
    public void testIgnoreClusterNameAllowsInitialization() throws Exception {
        startCluster(false);
        assertEquals(0, execute("-icl", "-cd", TEST_RESOURCE_ABSOLUTE_PATH));
        assertEquals(200, adminClient().executeGetRequest(".opendistro_security").getStatusCode());
    }

    @Test
    public void testMismatchDoesNotModifyExistingConfiguration() throws Exception {
        startCluster(true);
        RestHelper admin = adminClient();
        JsonNode originalRoles = getJson(admin, ".opendistro_security/_doc/roles");
        JsonNode originalIndexSettings = getJson(admin, ".opendistro_security/_settings");
        JsonNode originalClusterSettings = getJson(admin, "_cluster/settings");

        for (List<String> operation : List.of(
            List.of("-cd", TEST_RESOURCE_ABSOLUTE_PATH),
            List.of("-us", "0"),
            List.of("-rl"),
            List.of("-era"),
            List.of("-dra"),
            List.of("-esa"),
            List.of("-dci")
        )) {
            List<String> options = new ArrayList<>(List.of("-cn", "wrong-" + clusterInfo.clustername));
            options.addAll(operation);
            assertEquals(operation.toString(), -1, execute(options.toArray(new String[0])));
            assertEquals(originalRoles, getJson(admin, ".opendistro_security/_doc/roles"));
            assertEquals(originalIndexSettings, getJson(admin, ".opendistro_security/_settings"));
            assertEquals(originalClusterSettings, getJson(admin, "_cluster/settings"));
        }

        // Exercise operations that return before the later cluster-health check.
        assertEquals(0, execute("--clustername", clusterInfo.clustername, "-us", "0"));
        assertEquals(
            "0",
            getJson(admin, ".opendistro_security/_settings").at("/.opendistro_security/settings/index/number_of_replicas").asText()
        );
        assertEquals(0, execute("--ignore-clustername", "-rl"));
        assertEquals(-1, execute("-cn", clusterInfo.clustername, "-icl", "-rl"));
    }

    private void startCluster(boolean initialize) throws Exception {
        Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.resolveStore("node-0-keystore").path())
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.resolveStore("truststore").path())
            .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings, initialize, ClusterConfiguration.SINGLENODE);
    }

    private RestHelper adminClient() {
        RestHelper admin = restHelper();
        admin.enableHTTPClientSSL = true;
        admin.trustHTTPServerCertificate = true;
        admin.sendAdminCertificate = true;
        admin.keystore = "kirk-keystore";
        return admin;
    }

    private JsonNode getJson(RestHelper admin, String path) throws Exception {
        var response = admin.executeGetRequest(path);
        assertEquals(response.getBody(), 200, response.getStatusCode());
        return DefaultObjectMapper.readTree(response.getBody());
    }

    private int execute(String... options) throws Exception {
        String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";
        List<String> args = new ArrayList<>(
            List.of(
                "-ts",
                FileHelper.resolveStore(prefix + "truststore").path().toFile().getAbsolutePath(),
                "-ks",
                FileHelper.resolveStore(prefix + "kirk-keystore").path().toFile().getAbsolutePath(),
                "-p",
                String.valueOf(clusterInfo.httpPort),
                "-nhnv"
            )
        );
        args.addAll(List.of(options));
        return SecurityAdmin.execute(args.toArray(new String[0]));
    }
}
