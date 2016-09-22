/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard;

import io.netty.handler.ssl.OpenSsl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.xml.bind.DatatypeConverter;

import junit.framework.Assert;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.PluginAwareNode;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.floragunn.searchguard.ssl.SearchGuardSSLPlugin;
import com.google.common.base.Strings;

public abstract class AbstractUnitTest {

    static {

        System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " "
                + System.getProperty("os.version"));
        System.out.println("Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
        System.out.println("JVM Impl.: " + System.getProperty("java.vm.version") + " " + System.getProperty("java.vm.vendor") + " "
                + System.getProperty("java.vm.name"));
        System.out.println("Open SSL available: "+OpenSsl.isAvailable());
        System.out.println("Open SSL version: "+OpenSsl.versionString());
    }

    @Rule
    public TestName name = new TestName();
    protected final String clustername = "searchguard_ssl_testcluster";

    protected Node esNode1;
    private Node esNode2;
    private Node esNode3;
    private String httpHost = null;
    private int httpPort = -1;
    protected Set<InetSocketTransportAddress> httpAdresses = new HashSet<InetSocketTransportAddress>();
    protected String nodeHost;
    protected int nodePort;
    protected boolean enableHTTPClientSSL = false;
    protected boolean enableHTTPClientSSLv3Only = false;
    protected boolean sendHTTPClientCertificate = false;
    protected boolean trustHTTPServerCertificate = false;
    protected String keystore = "node-0-keystore.jks";

    @Rule
    public final TestWatcher testWatcher = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            final String methodName = description.getMethodName();
            String className = description.getClassName();
            className = className.substring(className.lastIndexOf('.') + 1);
            System.out.println("---------------- Starting JUnit-test: " + className + " " + methodName + " ----------------");
        }

        @Override
        protected void failed(final Throwable e, final Description description) {
            final String methodName = description.getMethodName();
            String className = description.getClassName();
            className = className.substring(className.lastIndexOf('.') + 1);
            System.out.println(">>>> " + className + " " + methodName + " FAILED due to " + e);
        }

        @Override
        protected void finished(final Description description) {
            // System.out.println("-----------------------------------------------------------------------------------------");
        }

    };

    protected AbstractUnitTest() {
        super();
    }

    // @formatter:off
    private Settings.Builder getDefaultSettingsBuilder(final int nodenum, final boolean dataNode, final boolean masterNode) {

        return Settings.settingsBuilder()
                .put("node.name", "searchguard_testnode_" + nodenum)
                .put("node.data", dataNode)
                .put("node.master", masterNode)
                .put("cluster.name", clustername)
                .put("path.data", "data/data")
                .put("path.work", "data/work")
                .put("path.logs", "data/logs")
                .put("path.conf", "data/config")
                .put("path.plugins", "data/plugins")
                .put("index.number_of_shards", "1")
                .put("index.number_of_replicas", "0")
                .put("http.enabled", true)
                .put("cluster.routing.allocation.disk.watermark.high","1mb")
                .put("cluster.routing.allocation.disk.watermark.low","1mb")
                .put("http.cors.enabled", true)
                .put("node.local", false)
                .put("path.home",".");
    }
    // @formatter:on

    protected final ESLogger log = Loggers.getLogger(this.getClass());

    protected final String getHttpServerUri() {
        final String address = "http" + (enableHTTPClientSSL ? "s" : "") + "://" + httpHost + ":" + httpPort;
        log.debug("Connect to {}", address);
        return address;
    }

    public final void startES(final Settings settings) throws Exception {

        FileUtils.deleteDirectory(new File("data"));

        esNode1 = new PluginAwareNode(getDefaultSettingsBuilder(1, false, true).put(
                settings == null ? Settings.Builder.EMPTY_SETTINGS : settings).build(), SearchGuardSSLPlugin.class, SearchGuardPlugin.class);
        esNode2 = new PluginAwareNode(getDefaultSettingsBuilder(2, true, true).put(
                settings == null ? Settings.Builder.EMPTY_SETTINGS : settings).build(), SearchGuardSSLPlugin.class, SearchGuardPlugin.class);
        esNode3 = new PluginAwareNode(getDefaultSettingsBuilder(3, true, false).put(
                settings == null ? Settings.Builder.EMPTY_SETTINGS : settings).build(), SearchGuardSSLPlugin.class, SearchGuardPlugin.class);

        esNode1.start();
        esNode2.start();
        esNode3.start();

        waitForGreenClusterState(esNode1.client());
    }
    
    protected Client client() {
        return esNode1.client();
    }

    @Before
    public void setUp() throws Exception {
        enableHTTPClientSSL = false;
        enableHTTPClientSSLv3Only = false;
    }

    @After
    public void tearDown() throws Exception {

        Thread.sleep(500);
        if (esNode3 != null) {
            esNode3.close();
        }

        if (esNode2 != null) {
            esNode2.close();
        }

        if (esNode1 != null) {
            esNode1.close();
        }
    }

    protected void waitForGreenClusterState(final Client client) throws IOException {
        waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(30), client);
    }

    protected void waitForCluster(final ClusterHealthStatus status, final TimeValue timeout, final Client client) throws IOException {
        try {
            log.debug("waiting for cluster state {}", status.name());
            final ClusterHealthResponse healthResponse = client.admin().cluster().prepareHealth().setWaitForStatus(status)
                    .setTimeout(timeout).setWaitForNodes("3").execute().actionGet();
            if (healthResponse.isTimedOut()) {
                throw new IOException("cluster state is " + healthResponse.getStatus().name() + " with "
                        + healthResponse.getNumberOfNodes() + " nodes");
            } else {
                log.debug("... cluster state ok " + healthResponse.getStatus().name() + " with " + healthResponse.getNumberOfNodes()
                        + " nodes");
            }
            
            org.junit.Assert.assertEquals(3, healthResponse.getNumberOfNodes());

            final NodesInfoResponse res = esNode1.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet();
            
            final NodeInfo[] nodes = res.getNodes();

            for (int i = 0; i < nodes.length; i++) {
                final NodeInfo nodeInfo = nodes[i];
                if (nodeInfo.getHttp() != null && nodeInfo.getHttp().address() != null) {
                    final InetSocketTransportAddress is = (InetSocketTransportAddress) nodeInfo.getHttp().address().publishAddress();
                    httpPort = is.getPort();
                    httpHost = is.getHost();
                    httpAdresses.add(is);
                }

                final InetSocketTransportAddress is = (InetSocketTransportAddress) nodeInfo.getTransport().getAddress().publishAddress();
                nodePort = is.getPort();
                nodeHost = is.getHost();
            }
        } catch (final ElasticsearchTimeoutException e) {
            throw new IOException("timeout, cluster does not respond to health request, cowardly refusing to continue with operations");
        }
    }

    public File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        File file = null;
        final URL fileUrl = AbstractUnitTest.class.getClassLoader().getResource(fileNameFromClasspath);
        if (fileUrl != null) {
            try {
                file = new File(URLDecoder.decode(fileUrl.getFile(), "UTF-8"));
            } catch (final UnsupportedEncodingException e) {
                return null;
            }

            if (file.exists() && file.canRead()) {
                return file;
            } else {
                log.error("Cannot read from {}, maybe the file does not exists? ", file.getAbsolutePath());
            }

        } else {
            log.error("Failed to load " + fileNameFromClasspath);
        }
        return null;
    }

    protected String executeSimpleRequest(final String request) throws Exception {

        CloseableHttpClient httpClient = null;
        CloseableHttpResponse response = null;
        try {
            httpClient = getHTTPClient();
            response = httpClient.execute(new HttpGet(getHttpServerUri() + "/" + request));

            if (response.getStatusLine().getStatusCode() >= 300) {
                throw new Exception("Statuscode " + response.getStatusLine().getStatusCode());
            }

            return IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
        } finally {

            if (response != null) {
                response.close();
            }

            if (httpClient != null) {
                httpClient.close();
            }
        }
    }
    
    protected class HttpResponse {
        private final CloseableHttpResponse inner;
        private final String body;
        private final Header[] header;
        private final int statusCode;
        private final String statusReason;

        public HttpResponse(CloseableHttpResponse inner) throws IllegalStateException, IOException {
            super();
            this.inner = inner;
            this.body = inner.getEntity() == null? null : IOUtils.toString(inner.getEntity().getContent(), StandardCharsets.UTF_8);
            this.header = inner.getAllHeaders();
            this.statusCode = inner.getStatusLine().getStatusCode();
            this.statusReason = inner.getStatusLine().getReasonPhrase();
            inner.close();
        }

        public CloseableHttpResponse getInner() {
            return inner;
        }

        public String getBody() {
            return body;
        }

        public Header[] getHeader() {
            return header;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getStatusReason() {
            return statusReason;
        }
        
        
        
    }
    
    protected HttpResponse executeGetRequest(final String request, Header... header) throws Exception {
        return executeRequest(new HttpGet(getHttpServerUri() + "/" + request), header);
    }
    
    protected HttpResponse executeHeadRequest(final String request, Header... header) throws Exception {
        return executeRequest(new HttpHead(getHttpServerUri() + "/" + request), header);
    }
    
    protected HttpResponse executePutRequest(final String request, String body, Header... header) throws Exception {
        HttpPut uriRequest = new HttpPut(getHttpServerUri() + "/" + request);
        if(!Strings.isNullOrEmpty(body)) {
            uriRequest.setEntity(new StringEntity(body));
        }
        
        return executeRequest(uriRequest, header);
        
    }
    
    protected HttpResponse executePostRequest(final String request, String body, Header... header) throws Exception {
        HttpPost uriRequest = new HttpPost(getHttpServerUri() + "/" + request);
        if(!Strings.isNullOrEmpty(body)) {
            uriRequest.setEntity(new StringEntity(body));
        }
        
        return executeRequest(uriRequest, header);
    }
    
    protected HttpResponse executeDeleteRequest(final String request, Header... header) throws Exception {
        return executeRequest(new HttpDelete(getHttpServerUri() + "/" + request), header);
    }
    
    protected HttpResponse executeRequest(HttpUriRequest uriRequest, Header... header) throws Exception {

        CloseableHttpClient httpClient = null;
        try {
            
            httpClient = getHTTPClient();
            
            if(header != null && header.length > 0) {
                for (int i = 0; i < header.length; i++) {
                    Header h = header[i];
                    uriRequest.addHeader(h);
                }
            }
            
            HttpResponse res = new HttpResponse(httpClient.execute(uriRequest));
            log.trace(res.getBody());
            return res;
        } finally {

            if (httpClient != null) {
                httpClient.close();
            }
        }
    }

    protected final CloseableHttpClient getHTTPClient() throws Exception {

        final HttpClientBuilder hcb = HttpClients.custom();

        if (enableHTTPClientSSL) {

            log.debug("Configure HTTP client with SSL");

            final KeyStore myTrustStore = KeyStore.getInstance("JKS");
            myTrustStore.load(new FileInputStream(getAbsoluteFilePathFromClassPath("truststore.jks")), "changeit".toCharArray());

            final KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(getAbsoluteFilePathFromClassPath(keystore)), "changeit".toCharArray());

            final SSLContextBuilder sslContextbBuilder = SSLContexts.custom().useTLS();

            if (trustHTTPServerCertificate) {
                sslContextbBuilder.loadTrustMaterial(myTrustStore);
            }

            if (sendHTTPClientCertificate) {
                sslContextbBuilder.loadKeyMaterial(keyStore, "changeit".toCharArray());
            }

            final SSLContext sslContext = sslContextbBuilder.build();

            String[] protocols = null;

            if (enableHTTPClientSSLv3Only) {
                protocols = new String[] { "SSLv3" };
            } else {
                protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
            }

            final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, protocols, null,
                    SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            hcb.setSSLSocketFactory(sslsf);
        }

        hcb.setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(60 * 1000).build());

        return hcb.build();
    }
    
    protected final String loadFile(final String file) throws IOException {
        final StringWriter sw = new StringWriter();
        IOUtils.copy(this.getClass().getResourceAsStream("/" + file), sw, StandardCharsets.UTF_8);
        return sw.toString();
    }
    
    protected BytesReference readYamlContent(final String file) {
            try {
                return readXContent(new StringReader(loadFile(file)), XContentType.YAML);
            } catch (IOException e) {
                return null;
            }
    }
    
    protected BytesReference readXContent(final Reader reader, final XContentType xContentType) throws IOException {
        XContentParser parser = null;
        try {
            parser = XContentFactory.xContent(xContentType).createParser(reader);
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            return builder.bytes();
        } finally {
            if (parser != null) {
                parser.close();
            }
        }
    }
    
    public static String encodeBasicHeader(final String username, final String password) {
        return new String(DatatypeConverter.printBase64Binary((username + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8)));
    }
}
