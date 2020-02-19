package com.amazon.opendistroforelasticsearch.security.ssl;

import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterConfiguration;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.io.File;

public class SSLCertReloadActionTests extends SingleClusterTest {

    private final String GET_TRANSPORT_DETAILS_ENDPOINT = "_opendistro/_security/nodecerts?pretty";
    private final String RELOAD_CERTS_ENDPOINT = "/_opendistro/_security/sslcerts/reload";

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Test
    public void testSSLReloadPass() throws Exception {
        final File transportPemCertFile = testFolder.newFile("node-temp-cert.pem");
        final File transportPemKeyFile = testFolder.newFile("node-temp-key.pem");
        final String transportPemCertFilePath = transportPemCertFile.getAbsolutePath();
        final String transportPemKeyFilePath = transportPemKeyFile.getAbsolutePath();
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), transportPemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), transportPemKeyFilePath);

        initTestCluster(transportPemCertFilePath, transportPemKeyFilePath, true);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "ssl/reload/kirk-keystore.jks";

        String transportInfoResponse = rh.executeSimpleRequest(GET_TRANSPORT_DETAILS_ENDPOINT);
        Assert.assertTrue(transportInfoResponse.contains("\"issuer_dn\" : \"CN=Example Com Inc. Signing CA, OU=Example Com Inc. Signing CA, O=Example Com Inc., DC=example, " +
            "DC=com\""));
        Assert.assertTrue(transportInfoResponse.contains("\"subject_dn\" : \"CN=node-1.example.com, OU=SSL, O=Test, L=Test, C=DE\""));
        Assert.assertTrue(transportInfoResponse.contains("\"not_before\" : \"2020-02-17T16:19:25.000Z\""));
        Assert.assertTrue(transportInfoResponse.contains("\"not_after\" : \"2022-02-16T16:19:25.000Z\""));

        // Test Valid Case: Change transport file details to "ssl/pem/node-new.crt.pem" and "ssl/pem/node-new.key.pem"
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node-new.crt.pem").toString(), transportPemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node-new.key.pem").toString(), transportPemKeyFilePath);
        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_CERTS_ENDPOINT, null);
        Assert.assertEquals(200, reloadCertsResponse.getStatusCode());
        Assert.assertEquals("{\"message\":\"updated certs successfully\"}", reloadCertsResponse.getBody());

        transportInfoResponse = rh.executeSimpleRequest(GET_TRANSPORT_DETAILS_ENDPOINT);
        Assert.assertTrue(transportInfoResponse.contains("\"issuer_dn\" : \"CN=Example Com Inc. Signing CA, OU=Example Com Inc. Signing CA, O=Example Com Inc., DC=example, DC=com\""));
        Assert.assertTrue(transportInfoResponse.contains("\"subject_dn\" : \"CN=node-1.example.com, OU=SSL, O=Test, L=Test, C=DE\""));
        Assert.assertTrue(transportInfoResponse.contains("\"not_before\" : \"2020-02-18T14:11:28.000Z\""));
        Assert.assertTrue(transportInfoResponse.contains("\"not_after\" : \"2022-02-17T14:11:28.000Z\""));
    }


    @Test
    public void testSSLReloadFail_UnAuthorizedUser() throws Exception {
        final String transportPemCertFilePath = testFolder.newFile("node-temp-cert.pem").getAbsolutePath();
        final String transportPemKeyFilePath = testFolder.newFile("node-temp-key.pem").getAbsolutePath();
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), transportPemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), transportPemKeyFilePath);

        initTestCluster(transportPemCertFilePath, transportPemKeyFilePath, true);

        // Test endpoint for non-admin user
        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "ssl/reload/spock-keystore.jks";

        final RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_CERTS_ENDPOINT, null);
        Assert.assertEquals(401, reloadCertsResponse.getStatusCode());
        Assert.assertEquals("Unauthorized", reloadCertsResponse.getStatusReason());
    }


    @Test
    public void testSSLReloadFail_InvalidDN() throws Exception {
        final String transportPemCertFilePath = testFolder.newFile("node-temp-cert.pem").getAbsolutePath();
        final String transportPemKeyFilePath = testFolder.newFile("node-temp-key.pem").getAbsolutePath();
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), transportPemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), transportPemKeyFilePath);

        initTestCluster(transportPemCertFilePath, transportPemKeyFilePath, true);
        
        // Test Invalid Case: Change transport file details to "ssl/pem/node-wrong.crt.pem"
        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "ssl/reload/kirk-keystore.jks";
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node-wrong.crt.pem").toString(), transportPemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node-wrong.key.pem").toString(), transportPemKeyFilePath);

        final RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_CERTS_ENDPOINT, null);
        Assert.assertEquals(500, reloadCertsResponse.getStatusCode());
        Assert.assertTrue(reloadCertsResponse.getBody().contains("Subject DN of new cert does not match"));
    }

    @Test
    public void testSSLReloadFail_NoReloadSet() throws Exception {
        final File transportPemCertFile = testFolder.newFile("node-temp-cert.pem");
        final File transportPemKeyFile = testFolder.newFile("node-temp-key.pem");
        final String transportPemCertFilePath = transportPemCertFile.getAbsolutePath();
        final String transportPemKeyFilePath = transportPemKeyFile.getAbsolutePath();
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), transportPemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), transportPemKeyFilePath);

        initTestCluster(transportPemCertFilePath, transportPemKeyFilePath, false);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "ssl/reload/kirk-keystore.jks";

        final RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_CERTS_ENDPOINT, "");
        Assert.assertEquals(400, reloadCertsResponse.getStatusCode());
        Assert.assertEquals("Bad Request", reloadCertsResponse.getStatusReason());
    }

    /**
     * Helper method to initialize test cluster for SSL Certificate Reload Tests
     * @param transportPemCertFilePath Absolute Path to transport pem cert file
     * @param transportPemKeyFilePath Absolute Path to transport pem key file
     * @param sslCertReload Sets the ssl cert reload flag
     */
    private void initTestCluster(final String transportPemCertFilePath, final String transportPemKeyFilePath, final boolean sslCertReload) throws Exception {
        final Settings settings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_ADMIN_DN, "CN=kirk,OU=client,O=client,L=Test,C=DE")
            .putList(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN, "C=DE,L=Test,O=Test,OU=SSL,CN=node-1.example.com")
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, transportPemCertFilePath)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, transportPemKeyFilePath)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/root-ca.pem"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/root-ca.pem"))
            .put(ConfigConstants.OPENDISTRO_SECURITY_SSL_CERT_RELOAD, sslCertReload)
            .build();

        final Settings initTransportClientSettings = Settings.builder()
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/truststore.jks"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/kirk-keystore.jks"))
            .build();

        setup(initTransportClientSettings, new DynamicSecurityConfig(), settings, true, ClusterConfiguration.DEFAULT);
    }

}
