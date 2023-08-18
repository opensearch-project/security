/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.bwc;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Assume;
import org.junit.Before;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import org.opensearch.Version;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import org.apache.hc.core5.http.HttpHost;

import org.opensearch.client.RestClient;
import org.opensearch.common.io.PathUtils;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Collection;
import org.opensearch.SpecialPermission;

public class SecurityBackwardsCompatibilityIT extends OpenSearchRestTestCase {

    private ClusterType CLUSTER_TYPE;
    private String CLUSTER_NAME;

    @Before
    private void testSetup() {
        final String bwcsuiteString = System.getProperty("tests.rest.bwcsuite");
        Assume.assumeTrue("Test cannot be run outside the BWC gradle task 'bwcTestSuite' or its dependent tasks", bwcsuiteString != null);
        CLUSTER_TYPE = ClusterType.parse(bwcsuiteString);
        CLUSTER_NAME = System.getProperty("tests.clustername");
    }

    @Override
    protected final boolean preserveIndicesUponCompletion() {
        return true;
    }

    @Override
    protected final boolean preserveReposUponCompletion() {
        return true;
    }

    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }

    // otherwise the generated urls are http://clustername...:port.../
    @Override
    protected String getProtocol() {
        return "https";
    }

    // Many changes from SecurityRestTestCase which replaces the rest client, not sure if this works
    // ../src/test/java/org/opensearch/security/sanity/tests/SecurityRestTestCase.java
    /** START SecurityRestTestCase */
    private static final String SECURITY_SSL_HTTP_ENABLED = "plugins.security.ssl.http.enabled";
    private static final String SECURITY_SSL_HTTP_CLIENTAUTH_MODE = "plugins.security.ssl.http.clientauth_mode";
    private static final String SECURITY_SSL_HTTP_KEYSTORE_ALIAS = "plugins.security.ssl.http.keystore_alias";
    private static final String SECURITY_SSL_HTTP_KEYSTORE_FILEPATH = "plugins.security.ssl.http.keystore_filepath";
    private static final String SECURITY_SSL_HTTP_PEMKEY_FILEPATH = "plugins.security.ssl.http.pemkey_filepath";
    private static final String SECURITY_SSL_HTTP_PEMCERT_FILEPATH = "plugins.security.ssl.http.pemcert_filepath";
    private static final String SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH = "plugins.security.ssl.http.pemtrustedcas_filepath";
    private static final String SECURITY_SSL_HTTP_KEYSTORE_TYPE = "plugins.security.ssl.http.keystore_type";
    private static final String SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS = "plugins.security.ssl.http.truststore_alias";
    private static final String SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH = "plugins.security.ssl.http.truststore_filepath";
    private static final String SECURITY_SSL_HTTP_TRUSTSTORE_TYPE = "plugins.security.ssl.http.truststore_type";

    @Override
    protected Settings restClientSettings() {
        return Settings.builder()
            .put("http.port", 9200)
            .put(SECURITY_SSL_HTTP_ENABLED, "true")
            .put(SECURITY_SSL_HTTP_PEMCERT_FILEPATH, "esnode.pem")
            .put(SECURITY_SSL_HTTP_PEMKEY_FILEPATH, "esnode-key.pem")
            .put(SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, "root-ca.pem")
            //.put(SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, "kirk-keystore.jks")
            .put("plugins.security.ssl.http.keystore_password", "changeit")
            .put("plugins.security.ssl.http.keystore_keypassword", "changeit")
            .build();
    }


    // Disabled security manager and didn't follow through if this was needed/not
    // @Override
    // protected RestClient buildClient(Settings settings, HttpHost[] hosts) throws IOException {
    //     System.out.println("What are the hosts" + Arrays.stream(hosts).map(h -> h.toHostString()).collect(Collectors.joining(",")));

    //     final SecurityManager sm = System.getSecurityManager();

    //     if (sm != null) {
    //         sm.checkPermission(new SpecialPermission());
    //     }

    //     final RestClient client = AccessController.doPrivileged(new PrivilegedAction<RestClient>() {
    //         @Override
    //         public RestClient run() {
    //             try {
    //                 return buildClient0(settings, hosts);
    //             } catch (IOException ioe) {
    //                 throw new RuntimeException(ioe);
    //             }
    //         }
    //     });
    //     return client;
    // }

    @Override
    protected RestClient buildClient(Settings settings, HttpHost[] hosts) throws IOException {
        String keystore = settings.get(SECURITY_SSL_HTTP_KEYSTORE_FILEPATH);

        if (keystore != null) {
            // create adminDN (super-admin) client
            // TODO: Don't know that this was needed - uses admin cert?, but the resolution of this path wasn't correct
            File file = new File("/Users/steecraw/security/bwc-test/src/test/resources/security/");
            Path configPath = PathUtils.get(file.toURI()).toAbsolutePath();
            return new SecureRestClientBuilder(settings, configPath).setSocketTimeout(60000).setConnectionRequestTimeout(180000).build();
        }

        // TODO: These should be part of the test properties
        // create client with passed user
        // TODO: updated property reference
        String userName = System.getProperty("tests.opensearch.username");
        String password = System.getProperty("tests.opensearch.password");

        return new SecureRestClientBuilder(hosts, true, userName, password).setSocketTimeout(60000)
            .setConnectionRequestTimeout(180000)
            .build();
    }

    /** END FROM SecurityRestTestCase */

    public void testBasicBackwardsCompatibility() throws Exception {
        String round = System.getProperty("tests.rest.bwcsuite_round");

        if (round.equals("first") || round.equals("old")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-0/plugins");
        } else if (round.equals("second")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-1/plugins");
        } else if (round.equals("third")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-2/plugins");
        }
    }

    private enum ClusterType {
        OLD,
        MIXED,
        UPGRADED;

        public static ClusterType parse(String value) {
            switch (value) {
                case "old_cluster":
                    return OLD;
                case "mixed_cluster":
                    return MIXED;
                case "upgraded_cluster":
                    return UPGRADED;
                default:
                    throw new AssertionError("unknown cluster type: " + value);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void assertPluginUpgrade(String uri) throws Exception {
        // This was adding in debugging, when there is a failure the node output is saved
        // Otherwise, manual inspection of the log files is recommend
        // ./security/bwc-test/build/testclusters/securityBwcCluster1-0/logs/opensearch.stdout.log
        // ./security/bwc-test/build/testclusters/securityBwcCluster1-1/logs/opensearch.stdout.log
        // ./security/bwc-test/build/testclusters/securityBwcCluster1-2/logs/opensearch.stdout.log
        // TODO: Make an issue about capturing the output from these cases better, even when they pass.

        // As written this test isn't using a user to make the call to _nodes, maybe as part of setup this is
        // handled, but we need a way to switch between different user accounts during the test.
        Map<String, Map<String, Object>> responseMap = (Map<String, Map<String, Object>>) getAsMap(uri).get("nodes");
        for (Map<String, Object> response : responseMap.values()) {
            List<Map<String, Object>> plugins = (List<Map<String, Object>>) response.get("plugins");
            Set<String> pluginNames = plugins.stream().map(map -> (String) map.get("name")).collect(Collectors.toSet());

            final Version minNodeVersion = this.minimumNodeVersion();

            if (minNodeVersion.major <= 1) {
                assertThat(pluginNames, hasItem("opensearch_security"));
            } else {
                assertThat(pluginNames, hasItem("opensearch-security"));
            }
        }
    }
}
