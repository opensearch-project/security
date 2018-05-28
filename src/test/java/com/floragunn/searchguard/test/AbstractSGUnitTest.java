/*
 * Copyright 2015-2017 floragunn GmbH
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

package com.floragunn.searchguard.test;

import io.netty.handler.ssl.OpenSsl;

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
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.test.helper.cluster.ClusterInfo;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;
import com.floragunn.searchguard.test.helper.rules.SGTestWatcher;

public abstract class AbstractSGUnitTest {
    
    protected static final AtomicLong num = new AtomicLong();

	static {

		System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " "
				+ System.getProperty("os.version"));
		System.out.println(
				"Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
		System.out.println("JVM Impl.: " + System.getProperty("java.vm.version") + " "
				+ System.getProperty("java.vm.vendor") + " " + System.getProperty("java.vm.name"));
		System.out.println("Open SSL available: " + OpenSsl.isAvailable());
		System.out.println("Open SSL version: " + OpenSsl.versionString());
		
	    //System.setProperty("sg.display_lic_none","true");
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

	@Rule
	public final TestWatcher testWatcher = new SGTestWatcher();

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
                .put("searchguard.ssl.transport.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks"))
                .put(initTransportClientSettings)
                .build();
        
        TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class));
        tc.addTransportAddress(new TransportAddress(new InetSocketAddress(info.nodeHost, info.nodePort)));
        return tc;
    }
    
    protected TransportClient getUserTransportClient(ClusterInfo info, String keyStore, Settings initTransportClientSettings) {
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        Settings tcSettings = Settings.builder()
                .put("cluster.name", info.clustername)
                .put("searchguard.ssl.transport.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+keyStore))
                .put(initTransportClientSettings)
                .build();
        
        TransportClient tc = new TransportClientImpl(tcSettings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class));
        tc.addTransportAddress(new TransportAddress(new InetSocketAddress(info.nodeHost, info.nodePort)));
        return tc;
    }
    
    protected void initialize(ClusterInfo info, Settings initTransportClientSettings, DynamicSgConfig sgconfig) {

        try (TransportClient tc = getInternalTransportClient(info, initTransportClientSettings)) {

            tc.addTransportAddress(new TransportAddress(new InetSocketAddress(info.nodeHost, info.nodePort)));
            Assert.assertEquals(info.numNodes,
                    tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            try {
                tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();
            } catch (Exception e) {
                //ignore
            }

            for(IndexRequest ir: sgconfig.getDynamicConfig(getResourceFolder())) {
                tc.index(ir).actionGet();
            }

            ConfigUpdateResponse cur = tc
                    .execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(ConfigConstants.CONFIG_NAMES.toArray(new String[0])))
                    .actionGet();
            Assert.assertEquals(info.numNodes, cur.getNodes().size());
            
            SearchResponse sr = tc.search(new SearchRequest("searchguard")).actionGet();
            //Assert.assertEquals(5L, sr.getHits().getTotalHits());
            
            sr = tc.search(new SearchRequest("searchguard")).actionGet();
            //Assert.assertEquals(5L, sr.getHits().getTotalHits());

            Assert.assertTrue(tc.get(new GetRequest("searchguard", "sg", "config")).actionGet().isExists());
            Assert.assertTrue(tc.get(new GetRequest("searchguard","sg","internalusers")).actionGet().isExists());
            Assert.assertTrue(tc.get(new GetRequest("searchguard","sg","roles")).actionGet().isExists());
            Assert.assertTrue(tc.get(new GetRequest("searchguard","sg","rolesmapping")).actionGet().isExists());
            Assert.assertTrue(tc.get(new GetRequest("searchguard","sg","actiongroups")).actionGet().isExists());
            Assert.assertFalse(tc.get(new GetRequest("searchguard","sg","rolesmapping_xcvdnghtu165759i99465")).actionGet().isExists());
            Assert.assertTrue(tc.get(new GetRequest("searchguard","sg","config")).actionGet().isExists());
        }
    }
    
    protected Settings.Builder minimumSearchGuardSettingsBuilder(int node) {
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        return Settings.builder()
                //.put("searchguard.ssl.transport.enabled", true)
                 //.put("searchguard.no_default_init", true)
                //.put("searchguard.ssl.http.enable_openssl_if_available", false)
                //.put("searchguard.ssl.transport.enable_openssl_if_available", false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put("searchguard.ssl.transport.keystore_alias", "node-0")
                .put("searchguard.ssl.transport.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+"node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .putList("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De");
                //.put(other==null?Settings.EMPTY:other);
    }
    
    protected NodeSettingsSupplier minimumSearchGuardSettings(Settings other) {
        return new NodeSettingsSupplier() {
            @Override
            public Settings get(int i) {
                return minimumSearchGuardSettingsBuilder(i).put(other).build();
            }
        };
    }
    
    protected void initialize(ClusterInfo info) {
        initialize(info, Settings.EMPTY, new DynamicSgConfig());
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
}
