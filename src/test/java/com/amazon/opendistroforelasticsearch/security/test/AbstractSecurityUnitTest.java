/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.junit.LoggerContextRule;
import org.apache.logging.log4j.test.appender.ListAppender;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Netty4Plugin;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestName;

import com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateAction;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateRequest;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateResponse;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterInfo;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

import io.netty.handler.ssl.OpenSsl;

public abstract class AbstractSecurityUnitTest {

    protected static final AtomicLong num = new AtomicLong();
    protected static boolean withRemoteCluster;

    static {

        System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " "
                + System.getProperty("os.version"));
        System.out.println(
                "Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
        System.out.println("JVM Impl.: " + System.getProperty("java.vm.version") + " "
                + System.getProperty("java.vm.vendor") + " " + System.getProperty("java.vm.name"));
        System.out.println("Open SSL available: " + OpenSsl.isAvailable());
        System.out.println("Open SSL version: " + OpenSsl.versionString());
        withRemoteCluster = Boolean.parseBoolean(System.getenv("OPENDISTRO_SECURITY_TEST_WITH_REMOTE_CLUSTER"));
        System.out.println("With remote cluster: " + withRemoteCluster);
        //System.setProperty("security.display_lic_none","true");
    }

    protected final Logger log = LogManager.getLogger(this.getClass());
    public static final ThreadPool MOCK_POOL = new ThreadPool(Settings.builder().put("node.name",  "mock").build());

    //TODO Test Matrix
    protected boolean allowOpenSSL = false; //disabled, we test this already in SSL Plugin
    //enable//disable enterprise modules
    //1node and 3 node

    @Rule
    public TestName name = new TestName();

    @Rule
    public final TemporaryFolder repositoryPath = new TemporaryFolder();

	//@Rule
	//public final TestWatcher testWatcher = new OpenDistroSecurityTestWatcher();

    public static Header encodeBasicHeader(final String username, final String password) {
        return new BasicHeader("Authorization", "Basic "+Base64.getEncoder().encodeToString(
                (username + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8)));
    }

    protected static class TransportClientImpl extends TransportClient {

        public TransportClientImpl(Settings settings, Collection<Class<? extends Plugin>> plugins) {
            super(settings, plugins);
        }

        public TransportClientImpl(Settings settings, Settings defaultSettings, Collection<Class<? extends Plugin>> plugins) {
            super(settings, defaultSettings, plugins, null);
        }
    }

    @SafeVarargs
    protected static Collection<Class<? extends Plugin>> asCollection(Class<? extends Plugin>... plugins) {
        return Arrays.asList(plugins);
    }


    protected TransportClient getInternalTransportClient(ClusterInfo info, Settings initTransportClientSettings) {

        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";

        Settings tcSettings = Settings.builder()
                .put("cluster.name", info.clustername)
                .put("opendistro_security.ssl.transport.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks"))
                .put("opendistro_security.ssl.transport.enforce_hostname_verification", false)
                .put("opendistro_security.ssl.transport.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks"))
                .put(initTransportClientSettings)
                .build();

        TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, OpenDistroSecurityPlugin.class));
        tc.addTransportAddress(new TransportAddress(new InetSocketAddress(info.nodeHost, info.nodePort)));
        return tc;
    }

    protected TransportClient getUserTransportClient(ClusterInfo info, String keyStore, Settings initTransportClientSettings) {

        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";

        Settings tcSettings = Settings.builder()
                .put("cluster.name", info.clustername)
                .put("opendistro_security.ssl.transport.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks"))
                .put("opendistro_security.ssl.transport.enforce_hostname_verification", false)
                .put("opendistro_security.ssl.transport.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+keyStore))
                .put(initTransportClientSettings)
                .build();

        TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, OpenDistroSecurityPlugin.class));
        tc.addTransportAddress(new TransportAddress(new InetSocketAddress(info.nodeHost, info.nodePort)));
        return tc;
    }

    protected void initialize(ClusterInfo info, Settings initTransportClientSettings, DynamicSecurityConfig securityConfig) {

        try (TransportClient tc = getInternalTransportClient(info, initTransportClientSettings)) {

            tc.addTransportAddress(new TransportAddress(new InetSocketAddress(info.nodeHost, info.nodePort)));
            Assert.assertEquals(info.numNodes,
                    tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            try {
                tc.admin().indices().create(new CreateIndexRequest("security")).actionGet();
            } catch (Exception e) {
                //ignore
            }

            for(IndexRequest ir: securityConfig.getDynamicConfig(getResourceFolder())) {
                tc.index(ir).actionGet();
            }

            ConfigUpdateResponse cur = tc
                    .execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(ConfigConstants.CONFIG_NAMES.toArray(new String[0])))
                    .actionGet();
            Assert.assertEquals(info.numNodes, cur.getNodes().size());

            SearchResponse sr = tc.search(new SearchRequest(".opendistro_security")).actionGet();
            //Assert.assertEquals(5L, sr.getHits().getTotalHits());

            sr = tc.search(new SearchRequest(".opendistro_security")).actionGet();
            //Assert.assertEquals(5L, sr.getHits().getTotalHits());

            Assert.assertTrue(tc.get(new GetRequest(".opendistro_security", "security", "config")).actionGet().isExists());
            Assert.assertTrue(tc.get(new GetRequest(".opendistro_security","security","internalusers")).actionGet().isExists());
            Assert.assertTrue(tc.get(new GetRequest(".opendistro_security","security","roles")).actionGet().isExists());
            Assert.assertTrue(tc.get(new GetRequest(".opendistro_security","security","rolesmapping")).actionGet().isExists());
            Assert.assertTrue(tc.get(new GetRequest(".opendistro_security","security","actiongroups")).actionGet().isExists());
            Assert.assertFalse(tc.get(new GetRequest(".opendistro_security","security","rolesmapping_xcvdnghtu165759i99465")).actionGet().isExists());
            Assert.assertTrue(tc.get(new GetRequest(".opendistro_security","security","config")).actionGet().isExists());
        }
    }

    protected Settings.Builder minimumSecuritySettingsBuilder(int node, boolean sslOnly) {

        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        Settings.Builder builder = Settings.builder()
                //.put("opendistro_security.ssl.transport.enabled", true)
                //.put("opendistro_security.no_default_init", true)
                //.put("opendistro_security.ssl.http.enable_openssl_if_available", false)
                //.put("opendistro_security.ssl.transport.enable_openssl_if_available", false)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put("opendistro_security.ssl.transport.keystore_alias", "node-0")
                .put("opendistro_security.ssl.transport.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+"node-0-keystore.jks"))
                .put("opendistro_security.ssl.transport.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks"))
                .put("opendistro_security.ssl.transport.enforce_hostname_verification", false);

        if(!sslOnly) {
            builder.putList("opendistro_security.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De");
            //.put(other==null?Settings.EMPTY:other);
        }

        return builder;
    }

    protected NodeSettingsSupplier minimumSecuritySettings(Settings other) {
        return new NodeSettingsSupplier() {
            @Override
            public Settings get(int i) {
                return minimumSecuritySettingsBuilder(i, false).put(other).build();
            }
        };
    }

    protected NodeSettingsSupplier minimumSecuritySettingsSslOnly(Settings other) {
        return new NodeSettingsSupplier() {
            @Override
            public Settings get(int i) {
                return minimumSecuritySettingsBuilder(i, true).put(other).build();
            }
        };
    }

    protected void initialize(ClusterInfo info) {
        initialize(info, Settings.EMPTY, new DynamicSecurityConfig());
    }

    protected void initialize(ClusterInfo info, DynamicSecurityConfig dynamicSgConfig) {
        initialize(info, Settings.EMPTY, dynamicSgConfig);
    }

    protected final void assertContains(HttpResponse res, String pattern) {
        Assert.assertTrue(WildcardMatcher.match(pattern, res.getBody()));
    }

    protected final void assertNotContains(HttpResponse res, String pattern) {
        Assert.assertFalse(WildcardMatcher.match(pattern, res.getBody()));
    }

    protected String getResourceFolder() {
        return null;
    }

    protected static ListAppender appender;

    @ClassRule
    public static LoggerContextRule init = new LoggerContextRule("log4j2-test.properties");

    @BeforeClass
    public static void setupLogging() {
        try {
            appender = init.getListAppender("list");
        } catch (Throwable e) {
            //ignore
        }
    }

    @Before
    public void clearAppender() {

        if(appender != null) {
            appender.clear();
        }
    }
}
