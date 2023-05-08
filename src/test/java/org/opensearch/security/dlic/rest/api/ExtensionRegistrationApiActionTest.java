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

package org.opensearch.security.dlic.rest.api;

import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.system_indices.SystemIndicesTests;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.junit.Assert.assertEquals;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class ExtensionRegistrationApiActionTest extends SystemIndicesTests {
    private final String ENDPOINT = PLUGINS_PREFIX + "/api/extensions/register";

    //Sample Request
    // {
    //  "unique_id": "hello_world",
    //  "indices": "messages",
    //  "protected_indices": {},
    //  "endpoints": "/hello, /goodbye",
    //  "protected_endpoints": "/update/{name}"
    //}
    private final String correctExtRequest = "     {\n" + "      \"unique_id\": \"hello_world\",\n" + "      \"indices\": \"messages\",\n" + "      \"protected_indices\": {},\n" + "      \"endpoints\": \"/hello, /goodbye\",\n" + "      \"protected_endpoints\": \"/update/{name}\"\n" + "    }";

    private final String wrongExtRequest = "     {\n"  + "      \"indices\": \"messages\",\n" + "      \"protected_indices\": {},\n" + "      \"endpoints\": \"/hello, /goodbye\",\n" + "      \"protected_endpoints\": \"/update/{name}\"\n" + "    }";

    private void setupSettingsWithSsl() throws Exception {

        Settings systemIndexSettings = Settings.builder()
                .put(ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY, false)
                .put("plugins.security.ssl.http.enabled",true)
                .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("path.repo", repositoryPath.getRoot().getAbsolutePath())
                .build();
        setup(Settings.EMPTY,
                new DynamicSecurityConfig()
                        .setConfig("config_system_indices.yml")
                        .setSecurityRoles("roles_system_indices.yml")
                        .setSecurityInternalUsers("internal_users_system_indices.yml")
                        .setSecurityRolesMapping("roles_mapping_system_indices.yml"),
                systemIndexSettings,
                true);
    }
    private RestHelper keyStoreRestHelper() {
        RestHelper restHelper = restHelper();
        restHelper.keystore = "kirk-keystore.jks";
        restHelper.enableHTTPClientSSL = true;
        restHelper.trustHTTPServerCertificate = true;
        restHelper.sendAdminCertificate = true;
        return restHelper;
    }

    private RestHelper sslRestHelper() {
        RestHelper restHelper = restHelper();
        restHelper.enableHTTPClientSSL = true;
        return restHelper;
    }
    @Test
    public void tempTestForExtensionRegistrationAPiActionRemoveAfter() throws Exception {
        setupSettingsWithSsl();

        RestHelper keyStoreRestHelper = keyStoreRestHelper();
        RestHelper sslRestHelper = sslRestHelper();

        String indexSettings = "{\n" +
                "    \"index\" : {\n" +
                "        \"refresh_interval\" : null\n" +
                "    }\n" +
                "}";

        //as Superadmin
        RestHelper.HttpResponse responsea = keyStoreRestHelper.executeGetRequest( ENDPOINT, indexSettings);
        assertEquals(RestStatus.CREATED.getStatus(), responsea.getStatusCode());

        responsea = keyStoreRestHelper.executePutRequest( ENDPOINT, indexSettings);
        assertEquals(RestStatus.CREATED.getStatus(), responsea.getStatusCode());

        //as admin
        //        responsea = sslRestHelper.executeGetRequest( ENDPOINT, indexSettings, allAccessUserHeader);
        //        assertEquals(RestStatus.CREATED.getStatus(), responsea.getStatusCode());
        //
        //        responsea = sslRestHelper.executePutRequest( ENDPOINT, indexSettings, allAccessUserHeader);
        //        assertEquals(RestStatus.CREATED.getStatus(), responsea.getStatusCode());
    }

}
