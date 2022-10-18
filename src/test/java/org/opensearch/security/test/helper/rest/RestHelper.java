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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.test.helper.rest;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.classic.methods.HttpDelete;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpHead;
import org.apache.hc.client5.http.classic.methods.HttpOptions;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpPut;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.test.helper.cluster.ClusterInfo;
import org.opensearch.security.test.helper.file.FileHelper;

import static org.junit.jupiter.api.Assertions.fail;

public class RestHelper {

	protected final Logger log = LogManager.getLogger(RestHelper.class);
	
	public boolean enableHTTPClientSSL = true;
	public boolean enableHTTPClientSSLv3Only = false;
	public boolean sendAdminCertificate = false;
	public boolean trustHTTPServerCertificate = true;
	public boolean sendHTTPClientCredentials = false;
	public String keystore = "node-0-keystore.jks";
	public final String prefix;
	//public String truststore = "truststore.jks";
	private ClusterInfo clusterInfo;
	
	public RestHelper(ClusterInfo clusterInfo, String prefix) {
		this.clusterInfo = clusterInfo;
		this.prefix = prefix;
	}
	
	public RestHelper(ClusterInfo clusterInfo, boolean enableHTTPClientSSL, boolean trustHTTPServerCertificate, String prefix) {
		this.clusterInfo = clusterInfo;
		this.enableHTTPClientSSL = enableHTTPClientSSL;
		this.trustHTTPServerCertificate = trustHTTPServerCertificate;
		this.prefix = prefix;
	}
	public String executeSimpleRequest(final String request) throws Exception {

		CloseableHttpClient httpClient = null;
		CloseableHttpResponse response = null;

		try {
			httpClient = getHTTPClient();
			response = httpClient.execute(new HttpGet(getRequestUri(request)));

			if (response.getCode() >= 300) {
				throw new Exception("Statuscode " + response.getCode());
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

	public HttpResponse[] executeMultipleAsyncPutRequest(final int numOfRequests, final String request, String body) throws Exception {
		final ExecutorService executorService = Executors.newFixedThreadPool(numOfRequests);
		Future<HttpResponse>[] futures = new Future[numOfRequests];
		for (int i = 0; i < numOfRequests; i++) {
			futures[i] = executorService.submit(() -> executePutRequest(request, body, new Header[0]));
		}
		executorService.shutdown();
		return Arrays.stream(futures)
				.map(HttpResponse::from)
				.toArray(s -> new HttpResponse[s]);
	}

	public HttpResponse executeGetRequest(final String request, Header... header) {
	    return executeRequest(new HttpGet(getRequestUri(request)), header);
	}

	public HttpResponse executeGetRequest(final String request, String body, Header... header) {
		HttpGet getRequest = new HttpGet(getRequestUri(request));
		getRequest.setEntity(createStringEntity(body));
		getRequest.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
		return executeRequest(getRequest, header);
	}
	
	public HttpResponse executeHeadRequest(final String request, Header... header) {
        return executeRequest(new HttpHead(getRequestUri(request)), header);
    }
	
	public HttpResponse executeOptionsRequest(final String request) {
        return executeRequest(new HttpOptions(getRequestUri(request)));
    }

	public HttpResponse executePutRequest(final String request, String body, Header... header) {
		HttpPut uriRequest = new HttpPut(getRequestUri(request));
		if (body != null && !body.isEmpty()) {
			uriRequest.setEntity(createStringEntity(body));
		}
		return executeRequest(uriRequest, header);
	}

	public HttpResponse executeDeleteRequest(final String request, Header... header) {
		return executeRequest(new HttpDelete(getRequestUri(request)), header);
	}

	public HttpResponse executeDeleteRequest(final String request, String body, Header... header) {
		HttpDelete delRequest = new HttpDelete(getRequestUri(request));
		delRequest.setEntity(createStringEntity(body));
		delRequest.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
		return executeRequest(delRequest, header);
	}


	public HttpResponse executePostRequest(final String request, String body, Header... header) {
		HttpPost uriRequest = new HttpPost(getRequestUri(request));
		if (body != null && !body.isEmpty()) {
			uriRequest.setEntity(createStringEntity(body));
		}

		return executeRequest(uriRequest, header);
	}
	
    public HttpResponse executePatchRequest(final String request, String body, Header... header) {
        HttpPatch uriRequest = new HttpPatch(getRequestUri(request));
        if (body != null && !body.isEmpty()) {
            uriRequest.setEntity(createStringEntity(body));
        }
        return executeRequest(uriRequest, header);
    }	
	
	public HttpResponse executeRequest(HttpUriRequest uriRequest, Header... header) {

		CloseableHttpClient httpClient = null;
		try {

			httpClient = getHTTPClient();

			if (header != null && header.length > 0) {
				for (int i = 0; i < header.length; i++) {
					Header h = header[i];
					uriRequest.addHeader(h);
				}
			}

			if (!uriRequest.containsHeader("Content-Type")) {
			    uriRequest.addHeader("Content-Type","application/json");
			}
			HttpResponse res = new HttpResponse(httpClient.execute(uriRequest));
			log.debug(res.getBody());
			return res;
		} catch (final Exception e) {
			throw new RuntimeException(e);
		} finally {

			if (httpClient != null) {
				try {
					httpClient.close();
				} catch (final Exception e) {
					throw new RuntimeException(e);
				}
			}
		}
	}

	private HttpEntity createStringEntity(String body) {
		return new StringEntity(body);
	}
	
	protected final String getHttpServerUri() {
		final String address = "http" + (enableHTTPClientSSL ? "s" : "") + "://" + clusterInfo.httpHost + ":" + clusterInfo.httpPort;
		log.debug("Connect to {}", address);
		return address;
	}

	protected final String getRequestUri(String request) {
		return getHttpServerUri() + "/" + StringUtils.strip(request, "/");
	}
	
	protected final CloseableHttpClient getHTTPClient() throws Exception {

		final HttpClientBuilder hcb = HttpClients.custom();

		if (sendHTTPClientCredentials) {
			UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("sarek", "sarek".toCharArray());
			BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
			credentialsProvider.setCredentials(new AuthScope(null, -1), credentials);
			hcb.setDefaultCredentialsProvider(credentialsProvider);
		}

		if (enableHTTPClientSSL) {

			log.debug("Configure HTTP client with SSL");
			
			if(prefix != null && !keystore.contains("/")) {
			    keystore = prefix+"/"+keystore;
			}
			
            final String keyStorePath = FileHelper.getAbsoluteFilePathFromClassPath(keystore).toFile().getParent();
                        
			final KeyStore myTrustStore = KeyStore.getInstance("JKS");
			myTrustStore.load(new FileInputStream(keyStorePath+"/truststore.jks"),
					"changeit".toCharArray());

			final KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath(keystore).toFile()), "changeit".toCharArray());

			final SSLContextBuilder sslContextbBuilder = SSLContexts.custom();

			if (trustHTTPServerCertificate) {
				sslContextbBuilder.loadTrustMaterial(myTrustStore, null);
			}

			if (sendAdminCertificate) {
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
					NoopHostnameVerifier.INSTANCE);

			final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
					.setSSLSocketFactory(sslsf)
					.setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(60, TimeUnit.SECONDS).build())
					.build();
			hcb.setConnectionManager(cm);
		}

		return hcb.build();
	}

	
	public static class HttpResponse {
		private final CloseableHttpResponse inner;
		private final String body;
		private final Header[] header;
		private final int statusCode;
		private final String statusReason;

		public HttpResponse(CloseableHttpResponse inner) throws IllegalStateException, IOException {
			super();
			this.inner = inner;
			final HttpEntity entity = inner.getEntity();
			if(entity == null) { //head request does not have a entity
			    this.body = "";
			} else {
			    this.body = IOUtils.toString(entity.getContent(), StandardCharsets.UTF_8);
			}
			this.header = inner.getHeaders();
			this.statusCode = inner.getCode();
			this.statusReason = inner.getReasonPhrase();
			inner.close();
		}

		public String getContentType() {
			Header h = getInner().getFirstHeader("content-type");
			if(h!= null) {
				return h.getValue();
			}
			return null;
		}

		public boolean isJsonContentType() {
			String ct = getContentType();
			if(ct == null) {
				return false;
			}
			return ct.contains("application/json");
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

		public List<Header> getHeaders() {
			return header==null?Collections.emptyList():Arrays.asList(header);
		}

        @Override
        public String toString() {
            return "HttpResponse [inner=" + inner + ", body=" + body + ", header=" + Arrays.toString(header) + ", statusCode=" + statusCode
                    + ", statusReason=" + statusReason + "]";
        }

		private static void findArrayAccessor(String input) {
			final Pattern r = Pattern.compile("(.+?)\\[(\\d+)\\]");
			final Matcher m = r.matcher(input);
			if(m.find()) {
				System.out.println("'" + input + "'\t Name was: " + m.group(1) + ",\t index position: " + m.group(2));
			} else {
				System.out.println("'" + input + "'\t No Match");
			}
		}

		/**
		 * Given a json path with dots delimiated returns the object at the leaf 
		 */
		public String findValueInJson(final String jsonDotPath) {
			// Make sure its json / then parse it
			if (!isJsonContentType()) {
				fail("Response was expected to be JSON, body was: \n" + body);
			}
			JsonNode currentNode = null;
			try {
				currentNode = DefaultObjectMapper.readTree(body);
			} catch (final Exception e) {
				throw new RuntimeException(e);
			}

			// Break the path into parts, and scan into the json object
			try (final Scanner jsonPathScanner = new Scanner(jsonDotPath).useDelimiter("\\.")) {
				if (!jsonPathScanner.hasNext()) {
					fail("Invalid json dot path '" + jsonDotPath + "', rewrite with '.' characters between path elements.");
				}
				do {
					String pathEntry = jsonPathScanner.next();
					// if pathEntry is an array lookup
					int arrayEntryIdx = -1;

					// Looks for an array-lookup pattern in the path
					// e.g. root_cause[1] -> will match
					// e.g. root_cause[2aasd] -> won't match
					final Pattern r = Pattern.compile("(.+?)\\[(\\d+)\\]");
					final Matcher m = r.matcher(pathEntry);
					if(m.find()) {
						pathEntry = m.group(1);
						arrayEntryIdx = Integer.parseInt(m.group(2));
					}

					if (!currentNode.has(pathEntry)) {
						fail("Unable to resolve '" + jsonDotPath + "', on path entry '" + pathEntry + "' from available fields " + currentNode.toPrettyString());
					}
					currentNode = currentNode.get(pathEntry);

					// if it's an Array lookup we get the requested index item
					if (arrayEntryIdx > -1) {
						if(!currentNode.isArray()) {
							fail("Unable to resolve '" + jsonDotPath + "', the '" + pathEntry + "' field is not an array " + currentNode.toPrettyString());
						} else if (!currentNode.has(arrayEntryIdx)) {
							fail("Unable to resolve '" + jsonDotPath + "', index '" + arrayEntryIdx + "' is out of bounds for array '" + pathEntry + "' \n" + currentNode.toPrettyString());
						}
						currentNode = currentNode.get(arrayEntryIdx);
					}
				} while (jsonPathScanner.hasNext());

				if (!currentNode.isValueNode()) {
					fail("Unexpected value note, index directly to the object to reference, object\n" + currentNode.toPrettyString());
				}
				return currentNode.asText();
			}
		}

		private static HttpResponse from(Future<HttpResponse> future) {
			try {
				return future.get();
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
	}

	
}
