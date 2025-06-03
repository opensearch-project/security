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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import com.carrotsearch.randomizedtesting.RandomizedContext;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Test;

import org.opensearch.common.CheckedConsumer;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.ssl.config.CertType;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.LocalOpenSearchCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.CERTS_INFO_ACTION;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public class CertificatesRestApiIntegrationTest extends AbstractApiIntegrationTest {
    final static String REST_API_ADMIN_SSL_INFO = "rest-api-admin-ssl-info";
    final static String REGULAR_USER = "regular_user";
    final static String ROOT_CA = "Root CA";

    static {
        testSecurityConfig.roles(
            new TestSecurityConfig.Role("simple_user_role").clusterPermissions("cluster:admin/security/certificates/info")
        )
            .rolesMapping(new TestSecurityConfig.RoleMapping("simple_user_role").users(REGULAR_USER, ADMIN_USER_NAME))
            .user(new TestSecurityConfig.User(REGULAR_USER))
            .withRestAdminUser(REST_ADMIN_USER, allRestAdminPermissions())
            .withRestAdminUser(REST_API_ADMIN_SSL_INFO, restAdminPermission(Endpoint.SSL, CERTS_INFO_ACTION));
    }

    @Override
    protected Map<String, Object> getClusterSettings() {
        Map<String, Object> clusterSettings = super.getClusterSettings();
        clusterSettings.put(SECURITY_RESTAPI_ADMIN_ENABLED, true);
        return clusterSettings;
    }

    @Override
    protected String apiPathPrefix() {
        return PLUGINS_PREFIX;
    }

    protected String sslCertsPath(String... path) {
        final var fullPath = new StringJoiner("/");
        fullPath.add(super.apiPath("certificates"));
        if (path != null) {
            for (final var p : path) {
                fullPath.add(p);
            }
        }
        return fullPath.toString();
    }

    @Test
    public void forbiddenForRegularUser() throws Exception {
        withUser(REGULAR_USER, client -> forbidden(() -> client.get(sslCertsPath())));
    }

    @Test
    public void forbiddenForAdminUser() throws Exception {
        withUser(ADMIN_USER_NAME, client -> forbidden(() -> client.get(sslCertsPath())));
    }

    @Test
    public void availableForTlsAdmin() throws Exception {
        withUser(ADMIN_USER_NAME, localCluster.getAdminCertificate(), verifySSLCertsInfo(List.of(CertType.HTTP, CertType.TRANSPORT, CertType.TRANSPORT_CLIENT)));
    }

    @Test
    public void availableForRestAdmin() throws Exception {
        withUser(REST_ADMIN_USER, verifySSLCertsInfo(List.of(CertType.HTTP, CertType.TRANSPORT, CertType.TRANSPORT_CLIENT)));
        withUser(REST_API_ADMIN_SSL_INFO, verifySSLCertsInfo(List.of(CertType.HTTP, CertType.TRANSPORT, CertType.TRANSPORT_CLIENT)));
    }

    @Test
    public void timeoutTest() throws Exception {
        withUser(REST_ADMIN_USER, this::verifyTimeoutRequest);
    }

    private void verifyTimeoutRequest(final TestRestClient client) throws Exception {
        ok(() -> client.get(sslCertsPath() + "?timeout=0"));
    }

    private CheckedConsumer<TestRestClient, Exception> verifySSLCertsInfo(List<CertType> expectCerts) {
        return testRestClient -> {
            try {
                assertSSLCertsInfo(localCluster.nodes(), expectCerts, ok(() -> testRestClient.get(sslCertsPath())));
                if (localCluster.nodes().size() > 1) {
                    final var randomNodes = randomNodes();
                    final var nodeIds = randomNodes.stream().map(n -> n.esNode().getNodeEnvironment().nodeId()).collect(Collectors.joining(","));
                    assertSSLCertsInfo(randomNodes, expectCerts, ok(() -> testRestClient.get(sslCertsPath(nodeIds))));
                }
                final var randomCertType = randomFrom(expectCerts);
                assertSSLCertsInfo(
                        localCluster.nodes(),
                        List.of(randomCertType),
                        ok(() -> testRestClient.get(String.format("%s?cert_type=%s", sslCertsPath(), randomCertType)))
                );
            } catch (Exception e) {
                fail("Verify SSLCerts info failed with exception: " + e.getMessage());
            }
        };
    }

    private void assertSSLCertsInfo(
        final List<LocalOpenSearchCluster.Node> expectedNode,
        final List<CertType> expectedCertTypes,
        final TestRestClient.HttpResponse response
    ) {
        final var body = response.bodyAsJsonNode();
        final var prettyStringBody = body.toPrettyString();
        final var _nodes = body.get("_nodes");
        assertThat(prettyStringBody, _nodes.get("total").asInt(), is(expectedNode.size()));
        assertThat(prettyStringBody, _nodes.get("successful").asInt(), is(expectedNode.size()));
        assertThat(prettyStringBody, _nodes.get("failed").asInt(), is(0));
        assertThat(prettyStringBody, body.get("cluster_name").asText(), is(localCluster.getClusterName()));
        final var nodes = body.get("nodes");
        for (final var n : expectedNode) {
            final var esNode = n.esNode();
            final var node = nodes.get(esNode.getNodeEnvironment().nodeId());
            assertThat(prettyStringBody, node.get("name").asText(), is(n.getNodeName()));
            assertThat(prettyStringBody, node.has("certificates"));
            final var certificates = node.get("certificates");
            /*
            Expect each node transport configured with root and issued cert.
            */
            for (CertType expectCert : expectedCertTypes) {
                final JsonNode transportCertificates = certificates.get(expectCert.id());
                assertThat(prettyStringBody, transportCertificates.isArray());
                assertThat(prettyStringBody, transportCertificates.size(), is(2));
                verifyCertsJson(n.nodeNumber(), transportCertificates.get(0));
                verifyCertsJson(n.nodeNumber(), transportCertificates.get(1));
            }
        }
    }

    private void verifyCertsJson(final int nodeNumber, final JsonNode jsonNode) {
        if (jsonNode.get("subject_dn").asText().contains(ROOT_CA)) { // handle root cert
            assertThat(
                    jsonNode.toPrettyString(),
                    jsonNode.get("subject_dn").asText(),
                    is(TestCertificates.CA_SUBJECT)
            );
            assertThat(jsonNode.toPrettyString(), jsonNode.get("san").asText().isEmpty());
        } else { // handle non-root
            assertThat(
                    jsonNode.toPrettyString(),
                    jsonNode.get("subject_dn").asText(),
                    is(String.format(TestCertificates.NODE_SUBJECT_PATTERN, nodeNumber))
            );
            assertThat(
                    jsonNode.toPrettyString(),
                    jsonNode.get("san").asText(),
                    containsString(String.format("node-%s.example.com", nodeNumber))
            );
        }
        assertThat(jsonNode.toPrettyString(), jsonNode.get("issuer_dn").asText(), is(TestCertificates.CA_SUBJECT));
        assertThat(jsonNode.toPrettyString(), jsonNode.has("not_before"));
        assertThat(jsonNode.toPrettyString(), jsonNode.has("not_after"));
    }

    private List<LocalOpenSearchCluster.Node> randomNodes() {
        final var nodes = localCluster.nodes();
        int leaveElements = randomIntBetween(1, nodes.size() - 1);
        return randomSubsetOf(leaveElements, nodes);
    }

    public <T> List<T> randomSubsetOf(int size, Collection<T> collection) {
        if (size > collection.size()) {
            throw new IllegalArgumentException(
                "Can't pick " + size + " random objects from a collection of " + collection.size() + " objects"
            );
        }
        List<T> tempList = new ArrayList<>(collection);
        Collections.shuffle(tempList, RandomizedContext.current().getRandom());
        return tempList.subList(0, size);
    }
}
