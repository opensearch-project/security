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

package org.opensearch.security.auditlog.integration;

import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.cluster.ClusterHelper;
import org.opensearch.security.test.helper.cluster.ClusterInfo;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class SSLAuditlogTest extends AbstractAuditlogiUnitTest {

    private ClusterInfo monitoringClusterInfo;
    private RestHelper rhMon;
    private final ClusterHelper monitoringCluster = new ClusterHelper(
        "mon_n" + num.incrementAndGet() + "_f" + System.getProperty("forkno") + "_t" + System.nanoTime()
    );

    @After
    @Override
    public void tearDown() {
        super.tearDown();
        try {
            monitoringCluster.stopCluster();
            monitoringClusterInfo = null;
        } catch (Exception e) {
            log.error("Failed to stop monitoring cluster {}.", monitoringClusterInfo.clustername, e);
            Assert.fail("Failed to stop monitoring cluster " + monitoringClusterInfo.clustername + ".");
        }
    }

    private void setupMonitoring() throws Exception {
        Assert.assertNull("No monitoring cluster", monitoringClusterInfo);
        monitoringClusterInfo = monitoringCluster.startCluster(
            minimumSecuritySettings(defaultNodeSettings(Settings.EMPTY)),
            ClusterConfiguration.DEFAULT
        );
        initialize(monitoringCluster, monitoringClusterInfo, new DynamicSecurityConfig());
        rhMon = new RestHelper(monitoringClusterInfo, getResourceFolder());
    }

    @Test
    public void testExternalPemUserPass() throws Exception {

        setupMonitoring();

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.audit.type", "external_opensearch")
            .put("plugins.security.audit.config.http_endpoints", monitoringClusterInfo.httpHost + ":" + monitoringClusterInfo.httpPort)
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "*spock*", "admin", "CN=kirk,OU=client,O=client,L=Test,C=DE")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
            .put(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL, true)
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX
                    + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH,
                false
            )
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX
                    + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("auditlog/chain-ca.pem")
            )
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("auditlog/spock.crtfull.pem")
            )
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("auditlog/spock.key.pem")
            )
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME,
                "admin"
            )
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD,
                "admin"
            )
            .build();

        setup(additionalSettings);
        HttpResponse response = rh.executeGetRequest("_search");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Thread.sleep(5000);
        response = rhMon.executeGetRequest("security-auditlog*/_refresh", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rhMon.executeGetRequest("security-auditlog*/_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertNotContains(response, "*\"hits\":{\"total\":0,*");
        assertContains(response, "*\"failed\":0},\"hits\":*");
    }

    @Test
    public void testExternalPemClientAuth() throws Exception {

        setupMonitoring();

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.audit.type", "external_opensearch")
            .put("plugins.security.audit.config.http_endpoints", monitoringClusterInfo.httpHost + ":" + monitoringClusterInfo.httpPort)
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "*spock*", "admin", "CN=kirk,OU=client,O=client,L=Test,C=DE")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
            .put(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL, true)
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX
                    + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH,
                true
            )
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX
                    + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("auditlog/chain-ca.pem")
            )
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("auditlog/kirk.crtfull.pem")
            )
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("auditlog/kirk.key.pem")
            )
            .build();

        setup(additionalSettings);
        HttpResponse response = rh.executeGetRequest("_search");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Thread.sleep(5000);
        response = rhMon.executeGetRequest("security-auditlog*/_refresh", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rhMon.executeGetRequest("security-auditlog*/_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertNotContains(response, "*\"hits\":{\"total\":0,*");
        assertContains(response, "*\"failed\":0},\"hits\":*");
    }

    @Test
    public void testExternalPemUserPassTp() throws Exception {

        setupMonitoring();

        Settings additionalSettings = Settings.builder()
            .put("plugins.security.audit.type", "external_opensearch")
            .put("plugins.security.audit.config.http_endpoints", monitoringClusterInfo.httpHost + ":" + monitoringClusterInfo.httpPort)
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "*spock*", "admin", "CN=kirk,OU=client,O=client,L=Test,C=DE")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
            .put(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL, true)
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX
                    + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("auditlog/chain-ca.pem")
            )
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME,
                "admin"
            )
            .put(
                ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD,
                "admin"
            )
            .build();

        setup(additionalSettings);
        HttpResponse response = rh.executeGetRequest("_search");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Thread.sleep(5000);
        response = rhMon.executeGetRequest("security-auditlog*/_refresh", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rhMon.executeGetRequest("security-auditlog-*/_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertNotContains(response, "*\"hits\":{\"total\":0,*");
        assertContains(response, "*\"failed\":0},\"hits\":*");
    }
}
