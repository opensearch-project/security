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
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AbstractAuditlogUnitTest;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

/**
 * Integration tests for CLUSTER_SETTINGS_CHANGED and INDEX_SETTINGS_CHANGED audit categories.
 * These tests run against a real single-node OpenSearch cluster with the security plugin.
 */
public class SettingsChangeAuditIntegrationTest extends AbstractAuditlogUnitTest {

    @Test
    public void testSettingsChangeAudit() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "AUTHENTICATED,GRANTED_PRIVILEGES")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true)
            .build();
        setup(settings);

        // test persistent cluster setting change
        TestAuditlogImpl.clear();
        HttpResponse response = rh.executePutRequest(
            "_cluster/settings",
            "{\"persistent\":{\"cluster.max_shards_per_node\":2000}}",
            encodeBasicHeader("admin", "admin")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Thread.sleep(1500);
        String auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("CLUSTER_SETTINGS_CHANGED"));
        Assert.assertTrue(auditlogs.contains("cluster.max_shards_per_node"));
        Assert.assertTrue(auditlogs.contains("2000"));
        Assert.assertTrue(auditlogs.contains("persistent"));
        Assert.assertTrue(auditlogs.contains("set"));
        validateMsgs(TestAuditlogImpl.messages);

        // test transient cluster setting change
        TestAuditlogImpl.clear();
        response = rh.executePutRequest(
            "_cluster/settings",
            "{\"transient\":{\"cluster.routing.allocation.enable\":\"primaries\"}}",
            encodeBasicHeader("admin", "admin")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Thread.sleep(1500);
        auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("CLUSTER_SETTINGS_CHANGED"));
        Assert.assertTrue(auditlogs.contains("cluster.routing.allocation.enable"));
        Assert.assertTrue(auditlogs.contains("transient"));
        validateMsgs(TestAuditlogImpl.messages);

        // test reset to default (removed)
        TestAuditlogImpl.clear();
        response = rh.executePutRequest(
            "_cluster/settings",
            "{\"persistent\":{\"cluster.max_shards_per_node\":null}}",
            encodeBasicHeader("admin", "admin")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Thread.sleep(1500);
        auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("CLUSTER_SETTINGS_CHANGED"));
        Assert.assertTrue(auditlogs.contains("cluster.max_shards_per_node"));
        Assert.assertTrue(auditlogs.contains("removed"));
        Assert.assertTrue(auditlogs.contains("2000")); // old_value
        validateMsgs(TestAuditlogImpl.messages);

        // test index setting change
        rh.executePutRequest("test-settings-idx", null, encodeBasicHeader("admin", "admin"));
        TestAuditlogImpl.clear();
        response = rh.executePutRequest(
            "test-settings-idx/_settings",
            "{\"index\":{\"number_of_replicas\":0}}",
            encodeBasicHeader("admin", "admin")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Thread.sleep(1500);
        auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("INDEX_SETTINGS_CHANGED"));
        Assert.assertTrue(auditlogs.contains("index.number_of_replicas"));
        Assert.assertTrue(auditlogs.contains("test-settings-idx"));
        validateMsgs(TestAuditlogImpl.messages);

        // test wildcard index resolution
        rh.executePutRequest("test-wild-001", null, encodeBasicHeader("admin", "admin"));
        rh.executePutRequest("test-wild-002", null, encodeBasicHeader("admin", "admin"));
        TestAuditlogImpl.clear();
        response = rh.executePutRequest(
            "test-wild-*/_settings",
            "{\"index\":{\"number_of_replicas\":0}}",
            encodeBasicHeader("admin", "admin")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Thread.sleep(1500);
        auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("INDEX_SETTINGS_CHANGED"));
        Assert.assertTrue(auditlogs.contains("test-wild-001"));
        Assert.assertTrue(auditlogs.contains("test-wild-002"));
        validateMsgs(TestAuditlogImpl.messages);

        // test sensitive setting redaction
        TestAuditlogImpl.clear();
        rh.executePutRequest(
            "_cluster/settings",
            "{\"persistent\":{\"plugins.security.ssl.transport.keystore_password\":\"mysecret\"}}",
            encodeBasicHeader("admin", "admin")
        );
        Thread.sleep(1500);
        auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertTrue(auditlogs.contains("CLUSTER_SETTINGS_CHANGED"));
        Assert.assertTrue(auditlogs.contains("***REDACTED***"));
        Assert.assertFalse(auditlogs.contains("mysecret"));
        validateMsgs(TestAuditlogImpl.messages);
    }

    @Test
    public void testSettingsChangeCategoryDisabled() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
            .put(
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                "AUTHENTICATED,GRANTED_PRIVILEGES,CLUSTER_SETTINGS_CHANGED,INDEX_SETTINGS_CHANGED"
            )
            .build();
        setup(settings);

        TestAuditlogImpl.clear();
        rh.executePutRequest(
            "_cluster/settings",
            "{\"persistent\":{\"cluster.max_shards_per_node\":2000}}",
            encodeBasicHeader("admin", "admin")
        );
        Thread.sleep(1500);
        String auditlogs = TestAuditlogImpl.sb.toString();
        Assert.assertFalse(auditlogs.contains("CLUSTER_SETTINGS_CHANGED"));
        Assert.assertFalse(auditlogs.contains("INDEX_SETTINGS_CHANGED"));
    }
}
