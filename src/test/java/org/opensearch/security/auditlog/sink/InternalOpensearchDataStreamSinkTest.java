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

package org.opensearch.security.auditlog.sink;

import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;

public class InternalOpensearchDataStreamSinkTest extends AbstractAuditlogiUnitTest {

    /**
     * Template for testing different configurations
     */
    public void testTemplate(Settings settings, String testTemplateName, String testDSName) throws Exception {

        setup(settings);

        setupStarfleetIndex();

        // Check index-template exists
        HttpResponse res = restHelper().executeGetRequest("_index_template/" + testTemplateName, encodeBasicHeader("admin", "admin"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(res.getTextFromJsonBody("/index_templates/0/index_template/data_stream/timestamp_field/name"), is("@timestamp"));

        clusterHelper.waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(10), 3);

        // Check datastream exists and state
        res = rh.executeGetRequest("_data_stream/" + testDSName, encodeBasicHeader("admin", "admin"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        assertThat(res.getTextFromJsonBody("/data_streams/0/name"), is(testDSName));
        assertThat(res.getTextFromJsonBody("/data_streams/0/generation"), is("1"));
        assertThat(res.getTextFromJsonBody("/data_streams/0/status"), is("GREEN"));

        // Check audit logs exists in the datastream
        // It may take some milliseconds before the auditlogs are written to the datstream.
        for (long stop = System.currentTimeMillis() + 4000; stop > System.currentTimeMillis();) {

            res = rh.executePostRequest(testDSName + "/_refresh", "{}", encodeBasicHeader("admin", "admin"));
            assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

            res = rh.executeGetRequest(
                testDSName + "/_search?q=audit_rest_request_path%3A%22%2Fsf%22",
                encodeBasicHeader("admin", "admin")
            );
            if (Integer.valueOf(res.getTextFromJsonBody("/hits/total/value")) > 0) {
                break;
            }
        }
        assertThat(Integer.valueOf(res.getTextFromJsonBody("/hits/total/value")), allOf(greaterThan(0), lessThan(10)));

        // Rollover auditlog index
        res = rh.executePostRequest(testDSName + "/_rollover", "{}", encodeBasicHeader("admin", "admin"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(res.getTextFromJsonBody("/acknowledged"), is("true"));

        clusterHelper.waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(10), 3);

        // Check datastream again
        // Now we have 2 backend indices.
        res = rh.executeGetRequest("_data_stream/" + testDSName, encodeBasicHeader("admin", "admin"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(res.getTextFromJsonBody("/data_streams/0/generation"), is("2"));
        assertThat(res.getTextFromJsonBody("/data_streams/0/status"), is("GREEN"));

        // Remove SF index and recreate it
        res = rh.executeDeleteRequest("sf", encodeBasicHeader("admin", "admin"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        setupStarfleetIndex();

        // Check audit logs exists in the datastream backend index
        // It may take some milliseconds before the auditlogs are written to the datstream.
        for (long stop = System.currentTimeMillis() + 4000; stop > System.currentTimeMillis();) {
            res = rh.executePostRequest(testDSName + "/_refresh", "{}", encodeBasicHeader("admin", "admin"));
            assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

            // Check there are audit logs in the rollovered backend index
            res = rh.executeGetRequest(
                ".ds-" + testDSName + "-000002/_search?q=audit_rest_request_path%3A%22%2Fsf%22",
                encodeBasicHeader("admin", "admin")
            );
            if (Integer.valueOf(res.getTextFromJsonBody("/hits/total/value")) > 0) {
                break;
            }
        }
        assertThat(Integer.valueOf(res.getTextFromJsonBody("/hits/total/value")), allOf(greaterThan(0), lessThan(10)));
    }

    @Test
    public void testDefaultSettings() throws Exception {

        // Set config to use a datastream as auditlog.
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", "internal_opensearch_data_stream")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
            .put("plugins.security.audit.threadpool.size", 10) // must be greater 0
            .build();
        this.testTemplate(settings, "opensearch-security-auditlog", "opensearch-security-auditlog");
    }

    @Test
    public void testCustomSettings() throws Exception {

        // Set config to use a datastream as auditlog.
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", "internal_opensearch_data_stream")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
            .put("plugins.security.audit.threadpool.size", 10) // must be greater 0
            .put("plugins.security.audit.config.data_stream.name", "datastream-security")
            .put("plugins.security.audit.config.data_stream.template.name", "template-security")

            .build();
        this.testTemplate(settings, "template-security", "datastream-security");
    }

    @Test
    public void testWithoutManagedtemplate() throws Exception {

        // Set config to use a datastream as auditlog.
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", "internal_opensearch_data_stream")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
            .put("plugins.security.audit.threadpool.size", 10) // must be greater 0
            .put("plugins.security.audit.config.data_stream.template.manage", false)
            .put("plugins.security.audit.config.data_stream.template.name", "template-security")
            .build();
        setup(settings);
        setupStarfleetIndex();

        // Check default index-template does NOT exists
        HttpResponse res = restHelper().executeGetRequest("_index_template/template-security", encodeBasicHeader("admin", "admin"));
        assertThat(res.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));
    }

    @Test
    public void testTemplateSettings() throws Exception {

        var numberOfShards = "5";
        var numberOfReplicas = "3";

        // Set config to use a datastream as auditlog.
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", "internal_opensearch_data_stream")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
            .put("plugins.security.audit.threadpool.size", 10) // must be greater 0
            .put("plugins.security.audit.config.data_stream.template.number_of_shards", numberOfShards)
            .put("plugins.security.audit.config.data_stream.template.number_of_replicas", numberOfReplicas)
            .build();
        setup(settings);
        setupStarfleetIndex();

        HttpResponse res = restHelper().executeGetRequest(
            "_index_template/opensearch-security-auditlog",
            encodeBasicHeader("admin", "admin")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(
            res.getTextFromJsonBody("/index_templates/0/index_template/template/settings/index/number_of_shards"),
            is(numberOfShards)
        );
        assertThat(
            res.getTextFromJsonBody("/index_templates/0/index_template/template/settings/index/number_of_replicas"),
            is(numberOfReplicas)
        );
    }
}
