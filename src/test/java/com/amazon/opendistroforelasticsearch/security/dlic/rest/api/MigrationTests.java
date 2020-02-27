/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class MigrationTests extends SingleClusterTest {

    @Test
    public void testSecurityMigrate() throws Exception {

        final Settings settings = Settings.builder().put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("opendistro_security.ssl.http.enabled", true)
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath",FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks")).build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executePostRequest("_opendistro/_security/api/migrate?pretty", "");
        assertContains(res, "*Migration completed*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executePostRequest("_opendistro/_security/api/migrate?pretty", "");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

        res = rh.executeGetRequest("_opendistro/_security/api/validate?pretty");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

    }

    @Test
    public void testSecurityMigrateInvalid() throws Exception {
        final Settings settings = Settings.builder().put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("opendistro_security.ssl.http.enabled", true)
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks"))
                .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, true)
                .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityInternalUsers("internal_users2.yml").setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executePostRequest("_opendistro/_security/api/migrate?pretty", "");
        assertContains(res, "*Migration completed*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executePostRequest("_opendistro/_security/api/migrate?pretty", "");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

        res = rh.executeGetRequest("_opendistro/_security/api/validate?pretty");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

    }

    @Test
    public void testSecurityValidate() throws Exception {
        final Settings settings = Settings.builder().put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("opendistro_security.ssl.http.enabled", true)
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks")).build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executeGetRequest("_opendistro/_security/api/validate?pretty");
        assertContains(res, "*OK*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

    }

    @Test
    public void testSecurityValidateWithInvalidConfig() throws Exception {
        final Settings settings = Settings.builder().put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("opendistro_security.ssl.http.enabled", true)
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks"))
                .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, true)
                .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityInternalUsers("internal_users2.yml").setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executeGetRequest("_opendistro/_security/api/validate?accept_invalid=true&pretty");
        assertContains(res, "*OK*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executeGetRequest("_opendistro/_security/api/validate?pretty");
        assertContains(res, "*Configuration is not valid*");
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, res.getStatusCode());

    }

    @Override
    protected String getType() {
        return "security";
    }

    @Override
    protected String getResourceFolder() {
        return "migration";
    }
}
