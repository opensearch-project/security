package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class TenantInfoActionTest extends AbstractRestApiUnitTest {
    private String payload = "{\"hosts\":[],\"users\":[\"sarek\"]," +
            "\"backend_roles\":[\"starfleet*\",\"ambassador\"],\"and_backend_roles\":[],\"description\":\"Migrated " +
            "from v6\"}";

    @Test
    public void testAllRolesNotContainMetaHeader() throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executeGetRequest("_opendistro/_security/tenantinfo");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_opendistro/_security/tenantinfo");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        rh.sendHTTPClientCredentials = true;
        response = rh.executeGetRequest("_opendistro/_security/tenantinfo");
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        rh.sendAdminCertificate = true;

        //update security config
        response = rh.executePatchRequest("/_opendistro/_security/api/securityconfig", "[{\"op\": \"replace\",\"path\": \"/config/dynamic/kibana/opendistro_role\",\"value\": \"opendistro_security_role_internal\"}]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest("/_opendistro/_security/api/rolesmapping/opendistro_security_role_internal", payload, new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executeGetRequest("_opendistro/_security/api/rolesmapping/opendistro_security_role_internal");

        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest("_opendistro/_security/tenantinfo");

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }
}
