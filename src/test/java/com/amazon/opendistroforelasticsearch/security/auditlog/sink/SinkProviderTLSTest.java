/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auditlog.sink;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.auditlog.helper.MockAuditMessageFactory;
import com.amazon.opendistroforelasticsearch.security.auditlog.helper.TestHttpHandler;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;

public class SinkProviderTLSTest {

	protected HttpServer server = null;

	@Before
	@After
	public void tearDown() {
		if (server != null) {
			try {
				server.stop();
			} catch (Exception e) {
				// ignore
			}
		}
	}

	@Test
	public void testTlsConfigurationNoFallback() throws Exception {

		TestHttpHandler handler = new TestHttpHandler();

		server = ServerBootstrap.bootstrap().setListenerPort(8083).setServerInfo("Test/1.1").setSslContext(createSSLContext()).registerHandler("*", handler).create();

		server.start();

		Builder builder = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/sink/configuration_tls.yml"));
		builder.put("path.home", "/");

		// replace some values with absolute paths for unit tests
		builder.put("opendistro_security.audit.config.webhook.ssl.pemtrustedcas_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/root-ca.pem"));
		builder.put("opendistro_security.audit.endpoints.endpoint1.config.webhook.ssl.pemtrustedcas_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/root-ca.pem"));
		builder.put("opendistro_security.audit.endpoints.endpoint2.config.webhook.ssl.pemtrustedcas_content", FileHelper.loadFile("auditlog/root-ca.pem"));

		SinkProvider provider = new SinkProvider(builder.build(), null, null, null);
		WebhookSink defaultSink = (WebhookSink) provider.defaultSink;
		Assert.assertEquals(true, defaultSink.verifySSL);

		AuditMessage msg = MockAuditMessageFactory.validAuditMessage();
		provider.allSinks.get("endpoint1").store(msg);

		Assert.assertTrue(handler.method.equals("POST"));
        Assert.assertTrue(handler.body != null);
        Assert.assertTrue(handler.body.contains("{"));
        assertStringContainsAllKeysAndValues(handler.body);

		handler.reset();

		provider.allSinks.get("endpoint2").store(msg);

		Assert.assertTrue(handler.method.equals("POST"));
        Assert.assertTrue(handler.body != null);
        Assert.assertTrue(handler.body.contains("{"));
        assertStringContainsAllKeysAndValues(handler.body);

		handler.reset();

		provider.defaultSink.store(msg);

		Assert.assertTrue(handler.method.equals("POST"));
        Assert.assertTrue(handler.body != null);
        Assert.assertTrue(handler.body.contains("{"));
        assertStringContainsAllKeysAndValues(handler.body);

        server.stop();
	}

	// for TLS support on our in-memory server
	private SSLContext createSSLContext() throws Exception {
			final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory
					.getDefaultAlgorithm());
			final KeyStore trustStore = KeyStore.getInstance("JKS");
			InputStream trustStream = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore.jks").toFile());
			trustStore.load(trustStream, "changeit".toCharArray());
			tmf.init(trustStore);

			final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			final KeyStore keyStore = KeyStore.getInstance("JKS");
			InputStream keyStream = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore.jks").toFile());

			keyStore.load(keyStream, "changeit".toCharArray());
			kmf.init(keyStore, "changeit".toCharArray());

			SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			return sslContext;
	}

	private void assertStringContainsAllKeysAndValues(String in) {
	    System.out.println(in);
		Assert.assertTrue(in, in.contains(AuditMessage.FORMAT_VERSION));
		Assert.assertTrue(in, in.contains(AuditMessage.CATEGORY));
		Assert.assertTrue(in, in.contains(AuditMessage.FORMAT_VERSION));
		Assert.assertTrue(in, in.contains(AuditMessage.REMOTE_ADDRESS));
		Assert.assertTrue(in, in.contains(AuditMessage.ORIGIN));
		Assert.assertTrue(in, in.contains(AuditMessage.REQUEST_LAYER));
		Assert.assertTrue(in, in.contains(AuditMessage.TRANSPORT_REQUEST_TYPE));
		Assert.assertTrue(in, in.contains(AuditMessage.UTC_TIMESTAMP));
		Assert.assertTrue(in, in.contains(AuditCategory.FAILED_LOGIN.name()));
		Assert.assertTrue(in, in.contains("FAILED_LOGIN"));
		Assert.assertTrue(in, in.contains("John Doe"));
		Assert.assertTrue(in, in.contains("8.8.8.8"));
		//Assert.assertTrue(in, in.contains("CN=kirk,OU=client,O=client,L=test,C=DE"));
	}
}
