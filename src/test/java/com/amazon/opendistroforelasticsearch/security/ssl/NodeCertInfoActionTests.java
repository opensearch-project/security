package com.amazon.opendistroforelasticsearch.security.ssl;

import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterConfiguration;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.unboundid.util.json.JSONObject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestStatus;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

public class NodeCertInfoActionTests extends SingleClusterTest {

    private final String ENDPOINT = "_opendistro/_security/nodecerts?pretty";

    @Test
    public void testNodeCertInfoPass() throws Exception {
        initTestCluster(true);
        final RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        final RestHelper.HttpResponse transportInfoRestResponse = rh.executeGetRequest(ENDPOINT);
        final String responseBody = transportInfoRestResponse.getBody();
        Assert.assertTrue(responseBody.contains(" \"issuer_dn\" : \"CN=Example Com Inc. Signing CA, OU=Example Com Inc. Signing CA, O=Example Com Inc., " +
            "DC=example, DC=com\""));
        Assert.assertTrue(responseBody.contains("\"not_before\" : \"2018-05-05T14:37:09.000Z\""));
        Assert.assertTrue(responseBody.contains("\"not_after\" : \"2028-05-02T14:37:09.000Z\""));
    }

    @Test
    public void testNodeCertInfoFail_NonAdmin() throws Exception {
        initTestCluster(true);
        final RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "spock-keystore.jks";

        final RestHelper.HttpResponse transportInfoRestResponse = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(401, transportInfoRestResponse.getStatusCode()); // Forbidden for non-admin
        Assert.assertEquals("Unauthorized", transportInfoRestResponse.getStatusReason());
    }

    @Test
    public void testNodeCertInfoFail_NoReloadSet() throws Exception {
        initTestCluster(false);
        final RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        final RestHelper.HttpResponse transportInfoRestResponse = rh.executeGetRequest(ENDPOINT);
        Assert.assertEquals(404, transportInfoRestResponse.getStatusCode());
        Assert.assertEquals("Not Found", transportInfoRestResponse.getStatusReason());
    }

    /**
     * Helper method to initialize test cluster for NodeCertInfo Tests
     * @param sslCertReload Sets the ssl cert reload flag
     */
    private void initTestCluster(boolean sslCertReload) throws Exception {
        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, FileHelper. getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, FileHelper. getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, FileHelper. getAbsoluteFilePathFromClassPath("ssl/root-ca.pem"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem"))
            .put(ConfigConstants.OPENDISTRO_SECURITY_SSL_CERT_RELOAD, sslCertReload)
            .build();
        setup(settings);
    }
}
