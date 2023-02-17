package org.opensearch.security.dlic.rest.api;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class TenancyConfigApiTest extends AbstractRestApiUnitTest {
    private final String BASE_ENDPOINT;
    private final String ENDPOINT;
    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public TenancyConfigApiTest(){
        BASE_ENDPOINT = getEndpointPrefix();
        ENDPOINT = getEndpointPrefix() + "/api/tenancyconfig";
    }

    @Test
    public void testTenancyConfigAPIAccess() throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        rh.sendHTTPClientCredentials = true;
        response = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }

    @Test
    public void testTenancyConfigAPIUpdate() throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCredentials = true;
        rh.sendAdminCertificate = true;

        //update security config
        RestHelper.HttpResponse response = rh.executePutRequest(ENDPOINT, FileHelper.loadFile("restapi/tenancyconfig.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        RestHelper.HttpResponse authinfo_response = rh.executeGetRequest(BASE_ENDPOINT + "/authinfo");

        Assert.assertEquals(authinfo_response.findValueInJson("tenancy_enabled"),"true");
        Assert.assertEquals(authinfo_response.findValueInJson("private_tenant_enabled"),"true");
        Assert.assertEquals(authinfo_response.findValueInJson("default_tenant"),"");

        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"/tenancy_config/multitenancy_enabled\"," +
                "\"value\": false}]", new Header[0]);

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        authinfo_response = rh.executeGetRequest(BASE_ENDPOINT + "/authinfo");

        Assert.assertEquals(authinfo_response.findValueInJson("tenancy_enabled"),"false");

        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"/tenancy_config/private_tenant_enabled\"," +
                "\"value\": false}]", new Header[0]);

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        authinfo_response = rh.executeGetRequest(BASE_ENDPOINT + "/authinfo");

        Assert.assertEquals(authinfo_response.findValueInJson("private_tenant_enabled"),"false");

        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"add\",\"path\": \"/tenancy_config/default_tenant\"," +
                "\"value\": \"Private\"}]", new Header[0]);

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        authinfo_response = rh.executeGetRequest(BASE_ENDPOINT + "/authinfo");

        Assert.assertEquals(authinfo_response.findValueInJson("default_tenant"),"Private");

        response = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

}
