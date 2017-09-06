/*
 * Copyright 2016 by floragunn UG (haftungsbeschränkt) - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * This software is free of charge for non-commercial and academic use. 
 * For commercial use in a production environment you have to obtain a license 
 * from https://floragunn.com
 * 
 */

package com.floragunn.searchguard.test;

import io.netty.handler.ssl.OpenSsl;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;

import javax.xml.bind.DatatypeConverter;

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
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.test.helper.cluster.ClusterInfo;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;
import com.floragunn.searchguard.test.helper.rules.SGTestWatcher;

public abstract class AbstractSGUnitTest {

	static {

		System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " "
				+ System.getProperty("os.version"));
		System.out.println(
				"Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
		System.out.println("JVM Impl.: " + System.getProperty("java.vm.version") + " "
				+ System.getProperty("java.vm.vendor") + " " + System.getProperty("java.vm.name"));
		System.out.println("Open SSL available: " + OpenSsl.isAvailable());
		System.out.println("Open SSL version: " + OpenSsl.versionString());
		
	    System.setProperty("jdk.tls.rejectClientInitiatedRenegotiation", "true");
	    System.setProperty("sg.display_lic_none","true");
	}
	
	protected final Logger log = LogManager.getLogger(this.getClass());
    public static final ThreadPool MOCK_POOL = new ThreadPool(Settings.builder().put("node.name",  "mock").build());
	
	@Rule
	public TestName name = new TestName();

	@Rule
	public final TestWatcher testWatcher = new SGTestWatcher();

	public static Header encodeBasicHeader(final String username, final String password) {
		return new BasicHeader("Authorization", "Basic "+new String(DatatypeConverter.printBase64Binary(
				(username + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8))));
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
        Settings tcSettings = Settings.builder()
                .put("cluster.name", info.clustername)
                .put("searchguard.ssl.transport.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
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

            tc.admin().indices().create(new CreateIndexRequest("searchguard")).actionGet();

            for(IndexRequest ir: sgconfig.getDynamicConfig()) {
                tc.index(ir).actionGet();
            }

            ConfigUpdateResponse cur = tc
                    .execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(ConfigConstants.CONFIG_NAMES.toArray(new String[0])))
                    .actionGet();
            Assert.assertEquals(info.numNodes, cur.getNodes().size());
            
            SearchResponse sr = tc.search(new SearchRequest("searchguard")).actionGet();
            Assert.assertEquals(5L, sr.getHits().getTotalHits());
            
            sr = tc.search(new SearchRequest("searchguard")).actionGet();
            Assert.assertEquals(5L, sr.getHits().getTotalHits());

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
        return Settings.builder().put("searchguard.ssl.transport.enabled", true)
                 //.put("searchguard.no_default_init", true)
                //.put("searchguard.ssl.http.enable_openssl_if_available", false)
                //.put("searchguard.ssl.transport.enable_openssl_if_available", false)
                .put("searchguard.ssl.transport.keystore_alias", "node-0")
                .put("searchguard.ssl.transport.keystore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath",
                        FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .putArray("searchguard.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De");
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
}
