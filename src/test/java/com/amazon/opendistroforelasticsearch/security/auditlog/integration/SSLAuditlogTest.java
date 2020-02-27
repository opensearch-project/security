/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auditlog.integration;

import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.auditlog.AbstractAuditlogiUnitTest;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterConfiguration;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterInfo;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class SSLAuditlogTest extends AbstractAuditlogiUnitTest {

    private ClusterInfo monitoringClusterInfo;
    private RestHelper rhMon;
    private final ClusterHelper monitoringCluster = new ClusterHelper("mon_n"+num.incrementAndGet()+"_f"+System.getProperty("forkno")+"_t"+System.nanoTime());

    @After
    public void tearDown() throws Exception {
        monitoringCluster.stopCluster();
    }

    private void setupMonitoring() throws Exception {
        monitoringClusterInfo =  monitoringCluster.startCluster(minimumSecuritySettings(defaultNodeSettings(Settings.EMPTY)), ClusterConfiguration.DEFAULT);
        initialize(monitoringClusterInfo, Settings.EMPTY, new DynamicSecurityConfig());
        rhMon = new RestHelper(monitoringClusterInfo, getResourceFolder());
    }


    @Test
    public void testExternalPemUserPass() throws Exception {

        setupMonitoring();

        Settings additionalSettings = Settings.builder()
                .put("opendistro_security.audit.type", "external_elasticsearch")
                .put("opendistro_security.audit.config.http_endpoints", monitoringClusterInfo.httpHost+":"+monitoringClusterInfo.httpPort)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_SIZE, 0)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "*spock*","admin", "CN=kirk,OU=client,O=client,L=Test,C=DE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL_CLIENT_AUTH, false)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_FILEPATH,
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/chain-ca.pem"))
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMCERT_FILEPATH,
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/spock.crtfull.pem"))
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_FILEPATH,
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/spock.key.pem"))
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_USERNAME,
                        "admin")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PASSWORD,
                        "admin")
                .build();

        setup(additionalSettings);
        HttpResponse response = rh.executeGetRequest("_search");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Thread.sleep(5000);
        response = rhMon.executeGetRequest("security-auditlog*/_refresh", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rhMon.executeGetRequest("security-auditlog*/_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(response.getBody());
        assertNotContains(response, "*\"hits\":{\"total\":0,*");
        assertContains(response, "*\"failed\":0},\"hits\":*");

    }

    @Test
    public void testExternalPemClientAuth() throws Exception {

        setupMonitoring();

        Settings additionalSettings = Settings.builder()
                .put("opendistro_security.audit.type", "external_elasticsearch")
                .put("opendistro_security.audit.config.http_endpoints", monitoringClusterInfo.httpHost+":"+monitoringClusterInfo.httpPort)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_SIZE, 0)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "*spock*","admin", "CN=kirk,OU=client,O=client,L=Test,C=DE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL_CLIENT_AUTH, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_FILEPATH,
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/chain-ca.pem"))
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMCERT_FILEPATH,
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/kirk.crtfull.pem"))
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_FILEPATH,
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/kirk.key.pem"))
                .build();

        setup(additionalSettings);
        HttpResponse response = rh.executeGetRequest("_search");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Thread.sleep(5000);
        response = rhMon.executeGetRequest("security-auditlog*/_refresh", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rhMon.executeGetRequest("security-auditlog*/_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(response.getBody());
        assertNotContains(response, "*\"hits\":{\"total\":0,*");
        assertContains(response, "*\"failed\":0},\"hits\":*");
    }

    @Test
    public void testExternalPemUserPassTp() throws Exception {

        setupMonitoring();

        Settings additionalSettings = Settings.builder()
                .put("opendistro_security.audit.type", "external_elasticsearch")
                .put("opendistro_security.audit.config.http_endpoints", monitoringClusterInfo.httpHost+":"+monitoringClusterInfo.httpPort)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_SIZE, 0)
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "*spock*","admin", "CN=kirk,OU=client,O=client,L=Test,C=DE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_FILEPATH,
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/chain-ca.pem"))
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_USERNAME,
                        "admin")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PASSWORD,
                        "admin")
                .build();

        setup(additionalSettings);
        HttpResponse response = rh.executeGetRequest("_search");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        Thread.sleep(5000);
        response = rhMon.executeGetRequest("security-auditlog*/_refresh", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rhMon.executeGetRequest("security-auditlog-*/_search", encodeBasicHeader("admin", "admin"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        System.out.println(response.getBody());
        assertNotContains(response, "*\"hits\":{\"total\":0,*");
        assertContains(response, "*\"failed\":0},\"hits\":*");
    }
}
