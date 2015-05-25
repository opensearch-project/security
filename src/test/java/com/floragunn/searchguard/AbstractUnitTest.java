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

import io.searchbox.client.JestResult;
import io.searchbox.client.config.HttpClientConfig;
import io.searchbox.core.Get;
import io.searchbox.core.Index;
import io.searchbox.core.Search;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLContext;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.impl.auth.NTLMSchemeFactory;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.mina.util.AvailablePortFinder;
import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthStatus;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.ImmutableSettings.Builder;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.NodeBuilder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.floragunn.searchguard.tests.EmbeddedLDAPServer;
import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public abstract class AbstractUnitTest {

    public static boolean debugAll = false;
    private static final File keytab = new File("target/tmp/keytab.keytab");
    protected static final Gson prettyGson = new GsonBuilder().setPrettyPrinting().create();

    static {

        System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " "
                + System.getProperty("os.version"));
        System.out.println("Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
        System.out.println("JVM Impl.: " + System.getProperty("java.vm.version") + " " + System.getProperty("java.vm.vendor") + " "
                + System.getProperty("java.vm.name"));

        if (debugAll) {
            System.setProperty("javax.net.debug", "all");
            System.setProperty("sun.security.krb5.debug", "true");
            System.setProperty("java.security.debug", "all");
        }

        try {

            String loginconf = FileUtils.readFileToString(SecurityUtil.getAbsoluteFilePathFromClassPath("login.conf_template"));
            loginconf = loginconf.replace("${debug}", String.valueOf(debugAll)).replace("${hostname}", getNonLocalhostAddress())
                    .replace("${keytab}", keytab.toURI().toString());

            final File loginconfFile = new File("target/tmp/login.conf");

            FileUtils.write(new File("target/tmp/login.conf"), loginconf);

            SecurityUtil.setSystemPropertyToAbsoluteFile("java.security.auth.login.config", loginconfFile.getAbsolutePath());
            SecurityUtil.setSystemPropertyToAbsoluteFilePathFromClassPath("java.security.krb5.conf", "krb5.conf");
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Rule
    public TestName name = new TestName();
    private HeaderAwareJestHttpClient client;
    protected final Map<String, Object> headers = new HashMap<String, Object>();
    protected final String clustername = "searchguard_testcluster";
    protected int elasticsearchHttpPort1;
    private int elasticsearchHttpPort2;
    private int elasticsearchHttpPort3;
    public int elasticsearchNodePort1;
    public int elasticsearchNodePort2;
    public int elasticsearchNodePort3;

    protected final int ldapServerPort = EmbeddedLDAPServer.ldapPort;
    protected final int ldapsServerPort = EmbeddedLDAPServer.ldapsPort;
    protected EmbeddedLDAPServer ldapServer;
    private Node esNode1;
    private Node esNode2;
    private Node esNode3;
    protected boolean enableSSL = false;
    protected boolean enableSSLv3Only = false;
    protected String username;
    protected String password;
    protected boolean useSpnego = false;

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
            //System.out.println("-----------------------------------------------------------------------------------------");
        }

    };

    protected AbstractUnitTest() {
        super();
    }

    protected Settings getAuthSettings(final boolean wrongPassword, final String... roles) {
        return cacheEnabled(false)
                .putArray("searchguard.authentication.authorization.settingsdb.roles." + username, roles)
                .put("searchguard.authentication.settingsdb.user." + username, password + (wrongPassword ? "-wrong" : ""))
                .put("searchguard.authentication.authorizer.impl",
                        "com.floragunn.searchguard.authorization.simple.SettingsBasedAuthorizator")
                        .put("searchguard.authentication.authentication_backend.impl",
                                "com.floragunn.searchguard.authentication.backend.simple.SettingsBasedAuthenticationBackend").build();
    }

    private Builder getDefaultSettingsBuilder(final int nodenum, final int nodePort, final int httpPort, final boolean dataNode,
            final boolean masterNode) {

        return ImmutableSettings.settingsBuilder().put("node.name", "searchguard_testnode_" + nodenum).put("node.data", dataNode)
                .put("node.master", masterNode).put("cluster.name", clustername).put("index.store.type", "memory")
                .put("index.store.fs.memory.enabled", "true").put("gateway.type", "none").put("path.data", "data/data")
                .put("path.work", "data/work").put("path.logs", "data/logs").put("path.conf", "data/config")
                .put("path.plugins", "data/plugins").put("index.number_of_shards", "3").put("index.number_of_replicas", "1")
                .put("http.port", httpPort).put("http.enabled", !dataNode).put("network.tcp.connect_timeout", 60000)
                .put("transport.tcp.port", nodePort).put("http.cors.enabled", true).put(ConfigConstants.SEARCHGUARD_CHECK_FOR_ROOT, false)
                .put(ConfigConstants.SEARCHGUARD_ALLOW_ALL_FROM_LOOPBACK, true).put("node.local", false);
    }

    protected final ESLogger log = Loggers.getLogger(this.getClass());

    protected final String getServerUri(final boolean connectFromLocalhost) {

        if (connectFromLocalhost) {
            return "http" + (enableSSL ? "s" : "") + "://localhost:" + elasticsearchHttpPort1;
        }

        final String nonLocalhostAdress = getNonLocalhostAddress();

        final String address = "http" + (enableSSL ? "s" : "") + "://" + nonLocalhostAdress + ":" + elasticsearchHttpPort1;
        log.debug("Connect to {}", address);
        return address;

    }

    public static String getNonLocalhostAddress() {

        try {
            for (final Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements();) {
                final NetworkInterface intf = en.nextElement();

                if (intf.isLoopback() || !intf.isUp()) {
                    continue;
                }

                for (final Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements();) {

                    final InetAddress ia = enumIpAddr.nextElement();

                    if (ia.isLoopbackAddress() || ia instanceof Inet6Address) {
                        continue;
                    }

                    return ia.getHostAddress();
                }
            }
        } catch (final SocketException e) {
            throw new RuntimeException(e);

        }

        System.out.println("ERROR: No non-localhost address available, will use localhost");
        return "localhost";
    }

    protected final String loadFile(final String file) throws IOException {

        final StringWriter sw = new StringWriter();
        IOUtils.copy(this.getClass().getResourceAsStream("/" + file), sw);
        return sw.toString();

    }

    public final void startES(final Settings settings) throws Exception {

        FileUtils.deleteDirectory(new File("data"));

        Set<Integer> ports = null;
        int offset = 0;
        final int windowsSize = 12;
        do {
            ports = AvailablePortFinder.getAvailablePorts(AvailablePortFinder.MAX_PORT_NUMBER - offset - windowsSize,
                    AvailablePortFinder.MAX_PORT_NUMBER - offset);
            offset += windowsSize;
        } while (ports.size() < 7);

        final Iterator<Integer> portIt = ports.iterator();

        elasticsearchHttpPort1 = portIt.next();
        elasticsearchHttpPort2 = portIt.next();
        elasticsearchHttpPort3 = portIt.next();

        elasticsearchNodePort1 = portIt.next();
        elasticsearchNodePort2 = portIt.next();
        elasticsearchNodePort3 = portIt.next();

        esNode1 = new NodeBuilder().settings(
                getDefaultSettingsBuilder(1, elasticsearchNodePort1, elasticsearchHttpPort1, false, true).put(
                        settings == null ? ImmutableSettings.Builder.EMPTY_SETTINGS : settings).build()).node();
        esNode2 = new NodeBuilder().settings(
                getDefaultSettingsBuilder(2, elasticsearchNodePort2, elasticsearchHttpPort2, true, true).put(
                        settings == null ? ImmutableSettings.Builder.EMPTY_SETTINGS : settings).build()).node();
        esNode3 = new NodeBuilder().settings(
                getDefaultSettingsBuilder(3, elasticsearchNodePort3, elasticsearchHttpPort3, true, false).put(
                        settings == null ? ImmutableSettings.Builder.EMPTY_SETTINGS : settings).build()).node();

        waitForGreenClusterState(esNode1.client());
    }

    public final void startLDAPServer() throws Exception {

        log.debug("non localhost address: {}", getNonLocalhostAddress());

        ldapServer = new EmbeddedLDAPServer();

        keytab.delete();
        ldapServer.createKeytab("krbtgt/EXAMPLE.COM@EXAMPLE.COM", "secret", keytab);
        ldapServer.createKeytab("HTTP/" + getNonLocalhostAddress() + "@EXAMPLE.COM", "httppwd", keytab);
        ldapServer.createKeytab("HTTP/localhost@EXAMPLE.COM", "httppwd", keytab);
        ldapServer.createKeytab("ldap/localhost@EXAMPLE.COM", "randall", keytab);

        ldapServer.start();
    }

    @Before
    public void setUp() throws Exception {

        headers.clear();
        username = password = null;
        enableSSL = false;

    }

    @After
    public void tearDown() throws Exception {

        // This will stop and clean the local node

        if (esNode3 != null) {
            esNode3.close();
        }

        if (esNode2 != null) {
            esNode2.close();
        }

        if (esNode1 != null) {
            esNode1.close();
        }

        if (client != null) {
            client.shutdownClient();
        }

        if (ldapServer != null) {
            ldapServer.stop();
        }

    }

    protected final Tuple<JestResult, HttpResponse> executeIndex(final String file, final String index, final String type, final String id,
            final boolean mustBeSuccesfull, final boolean connectFromLocalhost) throws Exception {

        client = getJestClient(getServerUri(connectFromLocalhost), username, password);

        final Tuple<JestResult, HttpResponse> restu = client.executeE(new Index.Builder(loadFile(file)).index(index).type(type).id(id)
                .refresh(true).setHeader(headers).build());

        final JestResult res = restu.v1();

        if (mustBeSuccesfull) {
            if (res.getErrorMessage() != null) {
                log.error("Index operation result: " + res.getErrorMessage());
            }
            Assert.assertTrue("Error msg: " + res.getErrorMessage() + res.getJsonString(), res.isSucceeded());
        } else {
            log.debug("Index operation result fails as expected: " + res.getErrorMessage());
            Assert.assertTrue(!res.isSucceeded());
        }

        return restu;
    }

    protected final Tuple<JestResult, HttpResponse> executeIndexAsString(final String string, final String index, final String type,
            final String id, final boolean mustBeSuccesfull, final boolean connectFromLocalhost) throws Exception {

        client = getJestClient(getServerUri(connectFromLocalhost), username, password);

        Index.Builder builder = new Index.Builder(string).index(index).type(type).refresh(true).setHeader(headers);
        if (id != null && id.length() > 0) {
            builder = builder.id(id);
        }

        final Tuple<JestResult, HttpResponse> restu = client.executeE(builder.build());

        final JestResult res = restu.v1();

        if (mustBeSuccesfull) {
            if (res.getErrorMessage() != null) {
                log.error("Index operation result: " + res.getErrorMessage());
            }
            Assert.assertTrue("Error msg: " + res.getErrorMessage() + res.getJsonString(), res.isSucceeded());
        } else {
            log.debug("Index operation result fails as expected: " + res.getErrorMessage());
            Assert.assertTrue(!res.isSucceeded());
        }

        return restu;
    }

    protected final Tuple<JestResult, HttpResponse> executeSearch(final String file, final String[] indices, final String[] types,
            final boolean mustBeSuccesfull, final boolean connectFromLocalhost) throws Exception {

        client = getJestClient(getServerUri(connectFromLocalhost), username, password);

        final Tuple<JestResult, HttpResponse> restu = client.executeE(new Search.Builder(loadFile(file))
        .addIndex(indices == null ? Collections.EMPTY_SET : Arrays.asList(indices))
        .addType(types == null ? Collections.EMPTY_SET : Arrays.asList(types)).refresh(true).setHeader(headers)

        .build());

        final JestResult res = restu.v1();

        if (mustBeSuccesfull) {
            if (res.getErrorMessage() != null) {
                log.error("Search operation result: {}", res.getErrorMessage());
            }
            Assert.assertTrue("Error msg: " + res.getErrorMessage() + res.getJsonString(), res.isSucceeded());
        } else {
            log.debug("Search operation fails as expected");
            Assert.assertTrue(!res.isSucceeded());
        }
        return restu;
    }

    protected final Tuple<JestResult, HttpResponse> executeGet(final String index, final String type, final String id,
            final boolean mustBeSuccesfull, final boolean connectFromLocalhost) throws Exception {

        client = getJestClient(getServerUri(connectFromLocalhost), username, password);

        final Tuple<JestResult, HttpResponse> restu = client.executeE(new Get.Builder(index, id).type(type).refresh(true)
                .setHeader(headers).build());

        final JestResult res = restu.v1();

        if (mustBeSuccesfull) {
            if (res.getErrorMessage() != null) {
                log.error("Get operation result: {}", res.getErrorMessage());
            }
            Assert.assertTrue("Error msg: " + res.getErrorMessage() + res.getJsonString(), res.isSucceeded());
        } else {
            log.debug("Get operation result fails as expected");
            Assert.assertTrue(!res.isSucceeded());
        }
        return restu;
    }

    protected final HeaderAwareJestHttpClient getJestClient(final String serverUri, final String username, final String password)
            throws Exception {// http://hc.apache.org/httpcomponents-client-ga/tutorial/html/authentication.html

        final CredentialsProvider credsProvider = new BasicCredentialsProvider();

        final HttpClientConfig clientConfig1 = new HttpClientConfig.Builder(serverUri).multiThreaded(true).build();

        // Construct a new Jest client according to configuration via factory
        final HeaderAwareJestClientFactory factory1 = new HeaderAwareJestClientFactory();

        factory1.setHttpClientConfig(clientConfig1);

        final HeaderAwareJestHttpClient c = factory1.getObject();

        final HttpClientBuilder hcb = HttpClients.custom();

        if (username != null) {
            credsProvider.setCredentials(new AuthScope(AuthScope.ANY), new UsernamePasswordCredentials(username, password));
        }

        if (useSpnego) {
            //SPNEGO/Kerberos setup
            log.debug("SPNEGO activated");
            final AuthSchemeProvider nsf = new SPNegoSchemeFactory(true);//  new NegotiateSchemeProvider();
            final Credentials jaasCreds = new JaasCredentials();
            credsProvider.setCredentials(new AuthScope(null, -1, null, AuthSchemes.SPNEGO), jaasCreds);
            credsProvider.setCredentials(new AuthScope(null, -1, null, AuthSchemes.NTLM), new NTCredentials("Guest", "Guest", "Guest",
                    "Guest"));
            final Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider> create()
                    .register(AuthSchemes.SPNEGO, nsf).register(AuthSchemes.NTLM, new NTLMSchemeFactory()).build();

            hcb.setDefaultAuthSchemeRegistry(authSchemeRegistry);
        }

        hcb.setDefaultCredentialsProvider(credsProvider);

        if (serverUri.startsWith("https")) {

            log.debug("Configure Jest with SSL");

            final KeyStore myTrustStore = KeyStore.getInstance("JKS");
            myTrustStore.load(new FileInputStream(SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")),
                    "changeit".toCharArray());

            final KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardKS.jks")), "changeit".toCharArray());

            final SSLContext sslContext = SSLContexts.custom().useTLS().loadKeyMaterial(keyStore, "changeit".toCharArray())
                    .loadTrustMaterial(myTrustStore).build();

            String[] protocols = null;

            if (enableSSLv3Only) {
                protocols = new String[] { "SSLv3" };
            } else {
                protocols = SecurityUtil.ENABLED_SSL_PROTOCOLS;
            }

            final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, protocols,
                    SecurityUtil.ENABLED_SSL_CIPHERS, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            hcb.setSSLSocketFactory(sslsf);

        }

        hcb.setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(60 * 1000).build());

        final CloseableHttpClient httpClient = hcb.build();

        c.setHttpClient(httpClient);
        return c;

    }

    protected final void setupTestData(final String searchGuardConfig) throws Exception {

        executeIndex("dummy_content.json", "ceo", "internal", "tp_1", true, true);
        executeIndex("dummy_content.json", "marketing", "flyer", "tp_2", true, true);
        executeIndex("dummy_content.json", "marketing", "customer", "tp_3", true, true);
        executeIndex("dummy_content.json", "marketing", "customer", "tp_4", true, true);
        executeIndex("dummy_content.json", "financial", "public", "t2p_5", true, true);
        executeIndex("dummy_content.json", "financial", "sensitivestuff", "t2p_6", true, true);
        executeIndex("dummy_content.json", "financial", "sensitivestuff", "t2p_7", true, true);

        for (int i = 0; i < 30; i++) {
            executeIndex("dummy_content.json", "public", "info", "t2pat_" + i, true, true);
        }

        executeIndex("dummy_content2.json", "future", "docs", "f_1", true, true);
        executeIndex("dummy_content2.json", "future", "docs", "f_2", true, true);

        esNode1.client().admin().indices().prepareAliases().addAlias(new String[] { "ceo", "financial" }, "crucial").execute().actionGet();
        esNode1.client().admin().indices().prepareAliases().addAlias(new String[] { "crucial", "marketing" }, "internal").execute()
        .actionGet();

        executeIndex(searchGuardConfig, "searchguard", "ac", "ac", true, true);
    }

    private static class JaasCredentials implements Credentials {

        @Override
        public String getPassword() {
            return null;
        }

        @Override
        public Principal getUserPrincipal() {
            return null;
        }
    }

    protected void waitForGreenClusterState(final Client client) throws IOException {
        waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(30), client);
    }

    protected void waitForCluster(final ClusterHealthStatus status, final TimeValue timeout, final Client client) throws IOException {
        try {
            log.debug("waiting for cluster state {}", status.name());
            final ClusterHealthResponse healthResponse = client.admin().cluster().prepareHealth().setWaitForStatus(status)
                    .setTimeout(timeout).execute().actionGet();
            if (healthResponse.isTimedOut()) {
                throw new IOException("cluster state is " + healthResponse.getStatus().name() + " and not " + status.name()
                        + ", cowardly refusing to continue with operations");
            } else {
                log.debug("... cluster state ok");
            }
        } catch (final ElasticsearchTimeoutException e) {
            throw new IOException("timeout, cluster does not respond to health request, cowardly refusing to continue with operations");
        }
    }

    protected void assertJestResultCount(final JestResult result, final int count) {
        Assert.assertNotNull(result);
        Assert.assertTrue(result.isSucceeded());
        Assert.assertEquals(count, result.getJsonObject().getAsJsonObject("hits").getAsJsonPrimitive("total").getAsInt());
    }

    protected void assertJestResultError(final JestResult result, final String... msgs) {
        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getErrorMessage());
        Assert.assertFalse(result.isSucceeded());

        if (msgs != null && msgs.length > 0) {
            boolean match = false;
            for (final String msg : msgs) {
                match = match || result.getErrorMessage().contains(msg);
            }
            Assert.assertTrue(result.getErrorMessage(), match);
        }
    }

    protected ImmutableSettings.Builder cacheEnabled(final boolean cache) {
        return ImmutableSettings.settingsBuilder().put("searchguard.authentication.authorizer.cache.enable", cache)
                .put("searchguard.authentication.authentication_backend.cache.enable", cache);
    }

    protected String toPrettyJson(final String json) {
        final Map jsonm = prettyGson.fromJson(json, Map.class);
        return prettyGson.toJson(jsonm);
    }

}
