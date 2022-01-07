/*
 * Copyright OpenSearch Contributors
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

package org.opensearch.security.dlic.rest.api;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import com.google.common.collect.ImmutableList;

import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

@RunWith(Parameterized.class)
public class SecurityConfigApiTest extends AbstractRestApiUnitTest {

    private final String ENDPOINT;

    public SecurityConfigApiTest(String endpoint){
        ENDPOINT = endpoint;
    }

    @Parameterized.Parameters
    public static Iterable<String> endpoints() {
        return ImmutableList.of(
                LEGACY_OPENDISTRO_PREFIX + "/api",
                PLUGINS_PREFIX + "/api"
        );
    }

    @Test
    public void testSecurityConfigApiRead() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePostRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePatchRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executeDeleteRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
    }
    
    @Test
    public void testSecurityConfigApiWrite() throws Exception {

        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/securityconfig/xxx", FileHelper.loadFile("restapi/securityconfig.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/securityconfig/config", FileHelper.loadFile("restapi/securityconfig.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest(ENDPOINT + "/securityconfig/config", FileHelper.loadFile("restapi/invalid_config.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        Assert.assertTrue(response.getContentType(), response.isJsonContentType());
        Assert.assertTrue(response.getBody().contains("Unrecognized field"));

        response = rh.executeGetRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePostRequest(ENDPOINT + "/securityconfig", "{\"xxx\": 1}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executePatchRequest(ENDPOINT + "/securityconfig", "[{\"op\": \"replace\",\"path\": \"/config/dynamic/hosts_resolver_mode\",\"value\": \"other\"}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeDeleteRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

    }

    @Test
    public void testSecurityConfigForHTTPPatch() throws Exception {

        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        //non-default config
        String updatedConfig = FileHelper.loadFile("restapi/securityconfig_nondefault.json");

        //update config
        HttpResponse response = rh.executePutRequest(ENDPOINT + "/securityconfig/config", updatedConfig, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        //make patch request
        response = rh.executePatchRequest(ENDPOINT + "/securityconfig", "[{\"op\": \"add\",\"path\": \"/config/dynamic/do_not_fail_on_forbidden\",\"value\": \"false\"}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        //get config
        response = rh.executeGetRequest(ENDPOINT + "/securityconfig", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // verify configs are same
        Assert.assertEquals(DefaultObjectMapper.readTree(updatedConfig), DefaultObjectMapper.readTree(response.getBody()).get("config"));


    }
}


