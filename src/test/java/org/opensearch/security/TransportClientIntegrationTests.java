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
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security;

import org.apache.http.Header;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.DocWriteResponse.Result;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;

public class TransportClientIntegrationTests extends SingleClusterTest {

	@Test
	public void testTransportClient() throws Exception {

		final Settings settings = Settings.builder()
				.putList(ConfigConstants.SECURITY_AUTHCZ_IMPERSONATION_DN+".CN=spock,OU=client,O=client,L=Test,C=DE", "worf", "nagilum")
				.put("discovery.initial_state_timeout","8s")
				.build();
		setup(settings);

		try (TransportClient tc = getInternalTransportClient()) {                    
			tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
		}


		Settings tcSettings = Settings.builder()
				.put(settings)
				.put("plugins.security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
				.put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
				.build();


		try (TransportClient tc = getInternalTransportClient(clusterInfo, tcSettings)) {         

			Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());


			CreateIndexResponse cir = tc.admin().indices().create(new CreateIndexRequest("vulcan")).actionGet();
			Assert.assertTrue(cir.isAcknowledged());


			IndexResponse ir = tc.index(new IndexRequest("vulcan").type("secrets").id("s1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"secret\":true}", XContentType.JSON)).actionGet();
			Assert.assertTrue(ir.getResult() == Result.CREATED);


			GetResponse gr =tc.prepareGet("vulcan", "secrets", "s1").setRealtime(true).get();
			Assert.assertTrue(gr.isExists());


			gr =tc.prepareGet("vulcan", "secrets", "s1").setRealtime(false).get();
			Assert.assertTrue(gr.isExists());


			SearchResponse actionGet = tc.search(new SearchRequest("vulcan").types("secrets")).actionGet();
			Assert.assertEquals(1, actionGet.getHits().getHits().length);

			gr =tc.prepareGet(".opendistro_security", "security", "config").setRealtime(false).get();
			Assert.assertFalse(gr.isExists());


			gr =tc.prepareGet(".opendistro_security", "security", "config").setRealtime(true).get();
			Assert.assertFalse(gr.isExists());


			actionGet = tc.search(new SearchRequest(".opendistro_security")).actionGet();
			Assert.assertEquals(0, actionGet.getHits().getHits().length);


			try {
				tc.index(new IndexRequest(".opendistro_security").type(getType()).id("config").source("config", FileHelper.readYamlContent("config.yml"))).actionGet();
				Assert.fail();
			} catch (Exception e) {
			}


			//impersonation
			try {

				StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
				try {
					tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "worf");
					gr = tc.prepareGet("vulcan", "secrets", "s1").get();
				} finally {
					ctx.close();
				}
				Assert.fail();
			} catch (OpenSearchSecurityException e) {
				Assert.assertTrue(e.getMessage(), e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
			}


			StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				Header header = encodeBasicHeader("worf", "worf");
				tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
				gr = tc.prepareGet("vulcan", "secrets", "s1").get();
				Assert.fail();
			} catch (OpenSearchSecurityException e) {
				Assert.assertTrue(e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
			} finally {
				ctx.close();
			}

			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				Header header = encodeBasicHeader("worf", "worf111");
				tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
				gr = tc.prepareGet("vulcan", "secrets", "s1").get();
				Assert.fail();
			} catch (OpenSearchSecurityException e) {
				e.printStackTrace();
				//Assert.assertTrue(e.getCause().getMessage().contains("password does not match"));
			} finally {
				ctx.close();
			}

			//impersonation
			try {
				ctx = tc.threadPool().getThreadContext().stashContext();
				try {
					tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "gkar");
					gr = tc.prepareGet("vulcan", "secrets", "s1").get();
					Assert.fail();
				} finally {
					ctx.close();
				}

			} catch (OpenSearchSecurityException e) {
				Assert.assertEquals("'CN=spock,OU=client,O=client,L=Test,C=DE' is not allowed to impersonate as 'gkar'", e.getMessage());
			}


			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				gr = tc.prepareGet(".opendistro_security", "security", "config").setRealtime(Boolean.TRUE).get();
				Assert.assertFalse(gr.isExists());
				Assert.assertTrue(gr.isSourceEmpty());
			} finally {
				ctx.close();
			}

			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				gr = tc.prepareGet(".opendistro_security", "config", "0").setRealtime(Boolean.FALSE).get();
				Assert.assertFalse(gr.isExists());
				Assert.assertTrue(gr.isSourceEmpty());
			} finally {
				ctx.close();
			}

			String scrollId = null;
			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				SearchResponse searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
				scrollId = searchRes.getScrollId();
			} finally {
				ctx.close();
			}


			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				tc.prepareSearchScroll(scrollId).get();
			} finally {
				ctx.close();
			}



			boolean ok=false;
			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				gr = tc.prepareGet("vulcan", "secrets", "s1").get();
				ok = true;
				ctx.close();
				ctx = tc.threadPool().getThreadContext().stashContext();
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				Header header = encodeBasicHeader("worf", "worf");
				tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
				gr = tc.prepareGet("vulcan", "secrets", "s1").get();
				Assert.fail();
			} catch (OpenSearchSecurityException e) {
				Assert.assertTrue(e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
				Assert.assertTrue(ok);
			} finally {
				ctx.close();
			}

			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				gr = tc.prepareGet(".opendistro_security", "security", "config").setRealtime(Boolean.TRUE).get();
				Assert.assertFalse(gr.isExists());
				Assert.assertTrue(gr.isSourceEmpty());
			} finally {
				ctx.close();
			}


			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				Header header = encodeBasicHeader("worf", "worf");
				tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
				gr = tc.prepareGet(".opendistro_security", "security", "config").setRealtime(Boolean.TRUE).get();
				Assert.fail();
			} catch (Exception e) {
				Assert.assertTrue(e.getMessage().contains("no permissions for [indices:data/read/get] and User [name=worf"));
			}
			finally {
				ctx.close();
			}



			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				Header header = encodeBasicHeader("nagilum", "nagilum");
				tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
				gr = tc.prepareGet(".opendistro_security", "security", "config").setRealtime(Boolean.TRUE).get();
				Assert.assertFalse(gr.isExists());
				Assert.assertTrue(gr.isSourceEmpty());
			} finally {
				ctx.close();
			}


			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				gr = tc.prepareGet(".opendistro_security", "security", "config").setRealtime(Boolean.FALSE).get();
				Assert.assertFalse(gr.isExists());
				Assert.assertTrue(gr.isSourceEmpty());
			} finally {
				ctx.close();
			}

			ctx = tc.threadPool().getThreadContext().stashContext();
			SearchResponse searchRes = null;
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
			} finally {
				ctx.close();
			}

			Assert.assertNotNull(searchRes.getScrollId());

			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "worf");
				tc.prepareSearchScroll(searchRes.getScrollId()).get(); 
				Assert.fail();
			} catch (Exception e) {
				Throwable root = ExceptionUtils.getRootCause(e);
				e.printStackTrace();
				Assert.assertTrue(root.getMessage().contains("Wrong user in reader context"));
			}
			finally {
				ctx.close();
			}


			ctx = tc.threadPool().getThreadContext().stashContext();
			searchRes = null;
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
				SearchResponse scrollRes = tc.prepareSearchScroll(searchRes.getScrollId()).get();
				Assert.assertEquals(0, scrollRes.getFailedShards());
			} finally {
				ctx.close();
			}

		}

	}

	@Test
	public void testTransportClientImpersonation() throws Exception {

		final Settings settings = Settings.builder()
				.putList("plugins.security.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "worf", "nagilum")
				.build();


		setup(settings);

		try (TransportClient tc = getInternalTransportClient()) {
			tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

			ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
			Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());

		}

		Settings tcSettings = Settings.builder()
				.put("plugins.security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
				.put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
				.put("path.home", ".")
				.put("request.headers.opendistro_security_impersonate_as", "worf")
				.build();

		try (TransportClient tc = getInternalTransportClient(clusterInfo, tcSettings)) {            
			NodesInfoRequest nir = new NodesInfoRequest();
			Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(nir).actionGet().getNodes().size());
		}
	}

	@Test
	public void testTransportClientImpersonationWildcard() throws Exception {

		final Settings settings = Settings.builder()
				.putList("plugins.security.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "*")
				.build();


		setup(settings);

		Settings tcSettings = Settings.builder()
				.put("plugins.security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
				.put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
				.put("path.home", ".")
				.put("request.headers.opendistro_security_impersonate_as", "worf")
				.build();

		try (TransportClient tc = getInternalTransportClient(clusterInfo, tcSettings)) {
			NodesInfoRequest nir = new NodesInfoRequest();
			Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(nir).actionGet().getNodes().size());
		}        
	}
	
	//---
	
	@Test
	public void testTransportClientUsernameAttribute() throws Exception {

		final Settings settings = Settings.builder()
				.putList(ConfigConstants.SECURITY_AUTHCZ_IMPERSONATION_DN+".CN=spock,OU=client,O=client,L=Test,C=DE", "worf", "nagilum")
				.put("discovery.initial_state_timeout","8s")
				.build();
		
		setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_transport_username.yml")
				.setSecurityRolesMapping("roles_mapping_transport_username.yml")
				.setSecurityInternalUsers("internal_users_transport_username.yml")
				, settings);
		
		try (TransportClient tc = getInternalTransportClient()) {                    
			tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
		}


		Settings tcSettings = Settings.builder()
				.put(settings)
				.put("plugins.security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
				.put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
				.build();


		try (TransportClient tc = getInternalTransportClient(clusterInfo, tcSettings)) {         

			Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());


			CreateIndexResponse cir = tc.admin().indices().create(new CreateIndexRequest("vulcan")).actionGet();
			Assert.assertTrue(cir.isAcknowledged());


			IndexResponse ir = tc.index(new IndexRequest("vulcan").type("secrets").id("s1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"secret\":true}", XContentType.JSON)).actionGet();
			Assert.assertTrue(ir.getResult() == Result.CREATED);


			GetResponse gr =tc.prepareGet("vulcan", "secrets", "s1").setRealtime(true).get();
			Assert.assertTrue(gr.isExists());


			gr =tc.prepareGet("vulcan", "secrets", "s1").setRealtime(false).get();
			Assert.assertTrue(gr.isExists());


			SearchResponse actionGet = tc.search(new SearchRequest("vulcan").types("secrets")).actionGet();
			Assert.assertEquals(1, actionGet.getHits().getHits().length);

			gr =tc.prepareGet(".opendistro_security", "security", "config").setRealtime(false).get();
			Assert.assertFalse(gr.isExists());


			gr =tc.prepareGet(".opendistro_security", "security", "config").setRealtime(true).get();
			Assert.assertFalse(gr.isExists());


			actionGet = tc.search(new SearchRequest(".opendistro_security")).actionGet();
			Assert.assertEquals(0, actionGet.getHits().getHits().length);


			try {
				tc.index(new IndexRequest(".opendistro_security").type(getType()).id("config").source("config", FileHelper.readYamlContent("config.yml"))).actionGet();
				Assert.fail();
			} catch (Exception e) {
			}


			//impersonation
			try {

				StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
				try {
					tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "worf");
					gr = tc.prepareGet("vulcan", "secrets", "s1").get();
				} finally {
					ctx.close();
				}
				Assert.fail();
			} catch (OpenSearchSecurityException e) {
				Assert.assertTrue(e.getMessage(), e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
			}


			StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				Header header = encodeBasicHeader("worf", "worf");
				tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
				gr = tc.prepareGet("vulcan", "secrets", "s1").get();
				Assert.fail();
			} catch (OpenSearchSecurityException e) {
				Assert.assertTrue(e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
			} finally {
				ctx.close();
			}

			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				Header header = encodeBasicHeader("worf", "worf111");
				tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
				gr = tc.prepareGet("vulcan", "secrets", "s1").get();
				Assert.fail();
			} catch (OpenSearchSecurityException e) {
				e.printStackTrace();
				//Assert.assertTrue(e.getCause().getMessage().contains("password does not match"));
			} finally {
				ctx.close();
			}

			//impersonation
			try {
				ctx = tc.threadPool().getThreadContext().stashContext();
				try {
					tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "gkar");
					gr = tc.prepareGet("vulcan", "secrets", "s1").get();
					Assert.fail();
				} finally {
					ctx.close();
				}

			} catch (OpenSearchSecurityException e) {
				Assert.assertEquals("'CN=spock,OU=client,O=client,L=Test,C=DE' is not allowed to impersonate as 'gkar'", e.getMessage());
			}


			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				gr = tc.prepareGet(".opendistro_security", "security", "config").setRealtime(Boolean.TRUE).get();
				Assert.assertFalse(gr.isExists());
				Assert.assertTrue(gr.isSourceEmpty());
			} finally {
				ctx.close();
			}

			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				gr = tc.prepareGet(".opendistro_security", "config", "0").setRealtime(Boolean.FALSE).get();
				Assert.assertFalse(gr.isExists());
				Assert.assertTrue(gr.isSourceEmpty());
			} finally {
				ctx.close();
			}

			String scrollId = null;
			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				SearchResponse searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
				scrollId = searchRes.getScrollId();
			} finally {
				ctx.close();
			}


			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				tc.prepareSearchScroll(scrollId).get();
			} finally {
				ctx.close();
			}



			boolean ok=false;
			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				gr = tc.prepareGet("vulcan", "secrets", "s1").get();
				ok = true;
				ctx.close();
				ctx = tc.threadPool().getThreadContext().stashContext();
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				Header header = encodeBasicHeader("worf", "worf");
				tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
				gr = tc.prepareGet("vulcan", "secrets", "s1").get();
				Assert.fail();
			} catch (OpenSearchSecurityException e) {
				Assert.assertTrue(e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
				Assert.assertTrue(ok);
			} finally {
				ctx.close();
			}

			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				gr = tc.prepareGet(".opendistro_security", "security", "config").setRealtime(Boolean.TRUE).get();
				Assert.assertFalse(gr.isExists());
				Assert.assertTrue(gr.isSourceEmpty());
			} finally {
				ctx.close();
			}


			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				Header header = encodeBasicHeader("worf", "worf");
				tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
				gr = tc.prepareGet(".opendistro_security", "security", "config").setRealtime(Boolean.TRUE).get();
				Assert.fail();
			} catch (Exception e) {
				Assert.assertTrue(e.getMessage().contains("no permissions for [indices:data/read/get] and User [name=worf"));
			}
			finally {
				ctx.close();
			}



			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				Header header = encodeBasicHeader("nagilum", "nagilum");
				tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
				gr = tc.prepareGet(".opendistro_security", "security", "config").setRealtime(Boolean.TRUE).get();
				Assert.assertFalse(gr.isExists());
				Assert.assertTrue(gr.isSourceEmpty());
			} finally {
				ctx.close();
			}


			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				gr = tc.prepareGet(".opendistro_security", "security", "config").setRealtime(Boolean.FALSE).get();
				Assert.assertFalse(gr.isExists());
				Assert.assertTrue(gr.isSourceEmpty());
			} finally {
				ctx.close();
			}

			ctx = tc.threadPool().getThreadContext().stashContext();
			SearchResponse searchRes = null;
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
			} finally {
				ctx.close();
			}

			Assert.assertNotNull(searchRes.getScrollId());

			ctx = tc.threadPool().getThreadContext().stashContext();
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "worf");
				tc.prepareSearchScroll(searchRes.getScrollId()).get(); 
				Assert.fail();
			} catch (Exception e) {
				Throwable root = ExceptionUtils.getRootCause(e);
				e.printStackTrace();
				Assert.assertTrue(root.getMessage().contains("Wrong user in reader context"));
			}
			finally {
				ctx.close();
			}


			ctx = tc.threadPool().getThreadContext().stashContext();
			searchRes = null;
			try {
				tc.threadPool().getThreadContext().putHeader("opendistro_security_impersonate_as", "nagilum");
				searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
				SearchResponse scrollRes = tc.prepareSearchScroll(searchRes.getScrollId()).get();
				Assert.assertEquals(0, scrollRes.getFailedShards());
			} finally {
				ctx.close();
			}

		}

	}

	@Test
	public void testTransportClientImpersonationUsernameAttribute() throws Exception {

		final Settings settings = Settings.builder()
				.putList("plugins.security.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "worf", "nagilum")
				.build();


		setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_transport_username.yml")
				.setSecurityRolesMapping("roles_mapping_transport_username.yml")
				.setSecurityInternalUsers("internal_users_transport_username.yml")
				, settings);

		try (TransportClient tc = getInternalTransportClient()) {
			tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();

			ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
			Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());

		}

		Settings tcSettings = Settings.builder()
				.put("plugins.security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
				.put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
				.put("path.home", ".")
				.put("request.headers.opendistro_security_impersonate_as", "worf")
				.build();

		try (TransportClient tc = getInternalTransportClient(clusterInfo, tcSettings)) {            
			NodesInfoRequest nir = new NodesInfoRequest();
			Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(nir).actionGet().getNodes().size());
		}
	}

	@Test
	public void testTransportClientImpersonationWildcardUsernameAttribute() throws Exception {

		final Settings settings = Settings.builder()
				.putList("plugins.security.authcz.impersonation_dn.CN=spock,OU=client,O=client,L=Test,C=DE", "*")
				.build();

		setup(Settings.EMPTY, new DynamicSecurityConfig().setConfig("config_transport_username.yml")
				.setSecurityRolesMapping("roles_mapping_transport_username.yml")
				.setSecurityInternalUsers("internal_users_transport_username.yml")
				, settings);
		
		Settings tcSettings = Settings.builder()
				.put("plugins.security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
				.put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
				.put("path.home", ".")
				.put("request.headers.opendistro_security_impersonate_as", "worf")
				.build();

		try (TransportClient tc = getInternalTransportClient(clusterInfo, tcSettings)) {
			NodesInfoRequest nir = new NodesInfoRequest();
			Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(nir).actionGet().getNodes().size());
		}        
	}

}
