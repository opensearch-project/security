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
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class ExtensionRegistrationApiActionTest extends AbstractRestApiUnitTest {
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

    @Test
    public void ShouldGetAuthTokenWhenRegistryGetsCreatedTest() throws Exception {

        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        RestHelper.HttpResponse response = rh.executePutRequest(ENDPOINT, correctExtRequest);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void RegisterExtShouldFailIfMissingFields() throws Exception {

        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        RestHelper.HttpResponse response = rh.executePutRequest(ENDPOINT, wrongExtRequest);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

}
