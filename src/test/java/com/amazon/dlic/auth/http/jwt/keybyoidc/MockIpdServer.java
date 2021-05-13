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

package com.amazon.dlic.auth.http.jwt.keybyoidc;

import static com.amazon.dlic.auth.http.jwt.keybyoidc.CxfTestTools.toJson;

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.http.HttpConnectionFactory;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.config.MessageConstraints;
import org.apache.http.entity.ContentLengthStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.ConnSupport;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.SSLServerSetupHandler;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.apache.http.io.HttpMessageParserFactory;
import org.apache.http.io.HttpMessageWriterFactory;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;

import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.network.SocketUtils;

class MockIpdServer implements Closeable {
	final static String CTX_DISCOVER = "/discover";
	final static String CTX_KEYS = "/api/oauth/keys";

	private final HttpServer httpServer;
	private final int port;
	private final String uri;
	private final boolean ssl;
	private final JsonWebKeys jwks;

	MockIpdServer(JsonWebKeys jwks) throws IOException {
		this(jwks, SocketUtils.findAvailableTcpPort(), false);
	}

	MockIpdServer(JsonWebKeys jwks, int port, boolean ssl) throws IOException {
		this.port = port;
		this.uri = (ssl ? "https" : "http") + "://localhost:" + port;
		this.ssl = ssl;
		this.jwks = jwks;

		ServerBootstrap serverBootstrap = ServerBootstrap.bootstrap().setListenerPort(port)
				.registerHandler(CTX_DISCOVER, new HttpRequestHandler() {

					@Override
					public void handle(HttpRequest request, HttpResponse response, HttpContext context)
							throws HttpException, IOException {

						handleDiscoverRequest(request, response, context);

					}
				}).registerHandler(CTX_KEYS, new HttpRequestHandler() {

					@Override
					public void handle(HttpRequest request, HttpResponse response, HttpContext context)
							throws HttpException, IOException {

						handleKeysRequest(request, response, context);

					}
				});

		if (ssl) {
			serverBootstrap = serverBootstrap.setSslContext(createSSLContext())
					.setSslSetupHandler(new SSLServerSetupHandler() {

						@Override
						public void initialize(SSLServerSocket socket) throws SSLException {
							socket.setNeedClientAuth(true);
						}
					}).setConnectionFactory(new HttpConnectionFactory<DefaultBHttpServerConnection>() {

						private ConnectionConfig cconfig = ConnectionConfig.DEFAULT;

						@Override
						public DefaultBHttpServerConnection createConnection(final Socket socket) throws IOException {
							final SSLTestHttpServerConnection conn = new SSLTestHttpServerConnection(
									this.cconfig.getBufferSize(), this.cconfig.getFragmentSizeHint(),
									ConnSupport.createDecoder(this.cconfig), ConnSupport.createEncoder(this.cconfig),
									this.cconfig.getMessageConstraints(), null, null, null, null);
							conn.bind(socket);
							return conn;
						}
					});
		}

		this.httpServer = serverBootstrap.create();

		httpServer.start();
	}

	@Override
	public void close() throws IOException {
		httpServer.stop();
	}

	public HttpServer getHttpServer() {
		return httpServer;
	}

	public String getUri() {
		return uri;
	}

	public String getDiscoverUri() {
		return uri + CTX_DISCOVER;
	}

	public int getPort() {
		return port;
	}

	protected void handleDiscoverRequest(HttpRequest request, HttpResponse response, HttpContext context)
			throws HttpException, IOException {
		response.setStatusCode(200);
		response.setHeader("Cache-Control", "public, max-age=31536000");
		response.setEntity(new StringEntity("{\"jwks_uri\": \"" + uri + CTX_KEYS + "\",\n" + "\"issuer\": \"" + uri
				+ "\", \"unknownPropertyToBeIgnored\": 42}"));
	}

	protected void handleKeysRequest(HttpRequest request, HttpResponse response, HttpContext context)
			throws HttpException, IOException {
		response.setStatusCode(200);
		response.setEntity(new StringEntity(toJson(jwks)));
	}

	private SSLContext createSSLContext() {
		if (!this.ssl) {
			return null;
		}

		try {
			final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			final KeyStore trustStore = KeyStore.getInstance("JKS");
			InputStream trustStream = new FileInputStream(
					FileHelper.getAbsoluteFilePathFromClassPath("jwt/truststore.jks").toFile());
			trustStore.load(trustStream, "changeit".toCharArray());
			tmf.init(trustStore);

			final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			final KeyStore keyStore = KeyStore.getInstance("JKS");
			InputStream keyStream = new FileInputStream(
					FileHelper.getAbsoluteFilePathFromClassPath("jwt/node-0-keystore.jks").toFile());

			keyStore.load(keyStream, "changeit".toCharArray());
			kmf.init(keyStore, "changeit".toCharArray());

			SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			return sslContext;
		} catch (GeneralSecurityException | IOException e) {
			throw new RuntimeException(e);
		}
	}

	static class SSLTestHttpServerConnection extends DefaultBHttpServerConnection {
		public SSLTestHttpServerConnection(final int buffersize, final int fragmentSizeHint,
				final CharsetDecoder chardecoder, final CharsetEncoder charencoder,
				final MessageConstraints constraints, final ContentLengthStrategy incomingContentStrategy,
				final ContentLengthStrategy outgoingContentStrategy,
				final HttpMessageParserFactory<HttpRequest> requestParserFactory,
				final HttpMessageWriterFactory<HttpResponse> responseWriterFactory) {
			super(buffersize, fragmentSizeHint, chardecoder, charencoder, constraints, incomingContentStrategy,
					outgoingContentStrategy, requestParserFactory, responseWriterFactory);
		}

		public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
			return ((SSLSocket) getSocket()).getSession().getPeerCertificates();
		}
	}
}
