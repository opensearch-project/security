/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AbstractAuditlogiUnitTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.auditlog.integration.TestAuditlogImpl;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;

import org.elasticsearch.common.settings.Settings;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

public class AuditLogApiActionTest extends AbstractAuditlogiUnitTest {
    private static final String ENDPOINT = "/_opendistro/_security/api/_auditlog";

    @Test
    public void testAuditLog() throws Exception {
        Settings additionalSettings = Settings.builder()
                .put("opendistro_security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, ENDPOINT)
                .build();
        setup(additionalSettings);

        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";

        AuditLogApiAction.AuditLogApiRequestContent content;
        String body;
        RestHelper.HttpResponse response;

        content = new AuditLogApiAction.AuditLogApiRequestContent(
                AuditCategory.BAD_HEADERS,
                null,
                null,
                ImmutableMap.of("Bad Header", ImmutableList.of("header1", "header2")),
                "192.168.1.0:80"
        );
        body = DefaultObjectMapper.writeValueAsString(content, true);

        TestAuditlogImpl.clear();

        response = rh.executePostRequest(ENDPOINT, body);
        log.error("Response {} {}", response.getStatusCode(), response.getBody());
        log.error("Audit log {}", TestAuditlogImpl.sb.toString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        content = new AuditLogApiAction.AuditLogApiRequestContent(
            AuditCategory.FAILED_LOGIN,
            "unknown",
            null,
            ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
            "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, true);

        TestAuditlogImpl.clear();

        response = rh.executePostRequest(ENDPOINT, body);
        log.error("Response {} {}", response.getStatusCode(), response.getBody());
        log.error("Audit log {}", TestAuditlogImpl.sb.toString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        content = new AuditLogApiAction.AuditLogApiRequestContent(
                AuditCategory.MISSING_PRIVILEGES,
                "unknown",
                null,
                ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
                "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, true);

        TestAuditlogImpl.clear();

        response = rh.executePostRequest(ENDPOINT, body);
        log.error("Response {} {}", response.getStatusCode(), response.getBody());
        log.error("Audit log {}", TestAuditlogImpl.sb.toString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        content = new AuditLogApiAction.AuditLogApiRequestContent(
                AuditCategory.SSL_EXCEPTION,
                null,
                null,
                ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
                "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, true);

        TestAuditlogImpl.clear();

        response = rh.executePostRequest(ENDPOINT, body);
        log.error("Response {} {}", response.getStatusCode(), response.getBody());
        log.error("Audit log {}", TestAuditlogImpl.sb.toString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        content = new AuditLogApiAction.AuditLogApiRequestContent(
                AuditCategory.AUTHENTICATED,
                "user",
                null,
                ImmutableMap.of("Authentication", ImmutableList.of("Basic: abcdef")),
                "192.168.1.0:80");
        body = DefaultObjectMapper.writeValueAsString(content, true);

        TestAuditlogImpl.clear();

        response = rh.executePostRequest(ENDPOINT, body);
        log.error("Response {} {}", response.getStatusCode(), response.getBody());
        log.error("Audit log {}", TestAuditlogImpl.sb.toString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }
}
