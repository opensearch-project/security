/*
 * Copyright OpenSearch Contributors
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

package org.opensearch.security.auditlog.sink;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.Settings.Builder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.auditlog.helper.MockAuditMessageFactory;
import org.opensearch.security.auditlog.helper.TestHttpHandler;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.test.helper.file.FileHelper;

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

        int port = findFreePort();
		server = ServerBootstrap.bootstrap().setListenerPort(port).setServerInfo("Test/1.1").setSslContext(createSSLContext()).registerHandler("*", handler).create();

		server.start();

		final byte[] configAsBytes = getConfigurationAsString(port).getBytes(StandardCharsets.UTF_8);
		Builder builder = Settings.builder().loadFromStream("configuration_tls.yml", new ByteArrayInputStream(configAsBytes), false);
		builder.put("path.home", "/");

		// replace some values with absolute paths for unit tests
		builder.put("plugins.security.audit.config.webhook.ssl.pemtrustedcas_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/root-ca.pem"));
		builder.put("plugins.security.audit.endpoints.endpoint1.config.webhook.ssl.pemtrustedcas_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/root-ca.pem"));
		builder.put("plugins.security.audit.endpoints.endpoint2.config.webhook.ssl.pemtrustedcas_content", FileHelper.loadFile("auditlog/root-ca.pem"));

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

	private int findFreePort() {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            return serverSocket.getLocalPort();
        } catch (Exception e) {
            throw new RuntimeException("Failed to find free port", e);
        }
    }

	private String getConfigurationAsString(final int port) {
		return "plugins.security.ssl.transport.enabled: true\n" +
"plugins.security.ssl.transport.keystore_filepath: \"transport.keystore_filepath\"\n" +
"plugins.security.ssl.transport.truststore_filepath: \"transport.truststore_filepath\"\n" +
"plugins.security.ssl.transport.enforce_hostname_verification: true\n" +
"plugins.security.ssl.transport.resolve_hostname: true\n" +
"plugins.security.ssl.transport.enable_openssl_if_available: true\n" +
"plugins.security.ssl.http.enabled: true\n" +
"plugins.security.ssl.http.keystore_filepath: \"http.keystore_filepath\"\n" +
"plugins.security.ssl.http.truststore_filepath: \"http.truststore_filepath\"\n" +
"plugins.security.ssl.http.enable_openssl_if_available: true\n" +
"plugins.security.ssl.http.clientauth_mode: OPTIONAL\n" +
"\n" +
"plugins.security:\n" +
"  audit:\n" +
"    type: webhook\n" +
"    config:\n" +
"      webhook:\n" +
"        url: https://localhost:" + port + "\n" +
"        format: JSON\n" +
"        ssl:\n" +
"          verify: true\n" +
"          pemtrustedcas_filepath: dyn\n" +
"    endpoints:\n" +
"      endpoint1:\n" +
"        type: webhook\n" +
"        config:\n" +
"          webhook:\n" +
"            url: https://localhost:" + port + "\n" +
"            format: JSON\n" +
"            ssl:\n" +
"              verify: true\n" +
"              pemtrustedcas_filepath: dyn\n" +
"      endpoint2:\n" +
"        type: webhook\n" +
"        config:\n" +
"          webhook:\n" +
"            url: https://localhost:" + port + "\n" +
"            format: JSON\n" +
"            ssl:\n" +
"              verify: true\n" +
"              pemtrustedcas_content: dyn\n" +
"      fallback:\n" +
"        type: org.opensearch.security.auditlog.helper.LoggingSink";
	}
}
