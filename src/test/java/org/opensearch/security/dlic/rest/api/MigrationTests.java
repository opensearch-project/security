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

package org.opensearch.security.dlic.rest.api;

import com.google.common.io.BaseEncoding;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import com.google.common.collect.ImmutableList;

@RunWith(Parameterized.class)
public class MigrationTests extends SingleClusterTest {
    private final String ENDPOINT;

    public MigrationTests(String endpoint){
        ENDPOINT = endpoint;
    }
    
    @Parameterized.Parameters
    public static Iterable<String> endpoints() {
        return ImmutableList.of(
                "_opendistro/_security/api",
                "_plugins/_security/api"
        );
    }

    @Test
    public void testSecurityMigrate() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put("plugins.security.ssl.http.enabled",true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks"))
            .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executePostRequest(ENDPOINT + "/migrate?pretty", "");
        assertContains(res, "*Migration completed*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executePostRequest(ENDPOINT + "/migrate?pretty", "");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

        res = rh.executeGetRequest(ENDPOINT + "/validate?pretty");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

    }

    @Test
    public void testSecurityMigrateInvalid() throws Exception {
        final Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks"))
            .put(ConfigConstants.SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, true)
            .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityInternalUsers("internal_users2.yml").setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executePostRequest(ENDPOINT + "/migrate?pretty", "");
        assertContains(res, "*Migration completed*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executePostRequest(ENDPOINT + "/migrate?pretty", "");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

        res = rh.executeGetRequest(ENDPOINT + "/validate?pretty");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());
    }

    @Test
    public void testSecurityValidate() throws Exception {
        final Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"))
             .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks")).build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executeGetRequest(ENDPOINT + "/validate?pretty");
        assertContains(res, "*OK*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

    }

    @Test
    public void testSecurityValidateWithInvalidConfig() throws Exception {
        final Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks"))
            .put(ConfigConstants.SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, true)
            .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityInternalUsers("internal_users2.yml").setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executeGetRequest(ENDPOINT + "/validate?accept_invalid=true&pretty");
        assertContains(res, "*OK*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executeGetRequest(ENDPOINT + "/validate?pretty");
        assertContains(res, "*Configuration is not valid*");
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, res.getStatusCode());

    }

    @Test
    public void testSecurityMigrateWithEmptyPassword() throws Exception{
        final Settings settings = Settings.builder().put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks"))
            .put(ConfigConstants.SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, true)
            .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityInternalUsers("internal_users2.yml").setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        String internalUsersWithEmptyPassword = "{\"logstash\":{\"hash\":\"\",\"roles\":[\"logstash\"]},\"Stephen_123\":{\"hash\":\"\", \"password\":\"\"},\"snapshotrestore\":{\"hash\":\"\",\"roles\":[\"snapshotrestore\"]},\"admin\":{\"attributes\":{\"attribute1\":\"value1\",\"attribute3\":\"value3\",\"attribute2\":\"value2\"},\"readonly\":\"true\",\"hash\":\"\",\"roles\":[\"admin\"]},\"kibanaserver\":{\"readonly\":\"true\",\"hash\":\"\"},\"kibanaro\":{\"hash\":\"\",\"roles\":[\"kibanauser\",\"readall\"]},\"readall\":{\"hash\":\"\",\"roles\":[\"readall\"]}}";
        String encodedInternalUsersWithEmptyPassword = BaseEncoding.base64().encode(internalUsersWithEmptyPassword.getBytes());
        String body = "{\"internalusers\":\"" + encodedInternalUsersWithEmptyPassword+ "\"}";
        HttpResponse res = rh.executePutRequest(".opendistro_security/_doc/internalusers", body);
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executePostRequest(ENDPOINT + "/migrate?pretty", "");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
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