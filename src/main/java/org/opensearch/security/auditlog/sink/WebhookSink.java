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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivilegedAction;
import java.security.cert.X509Certificate;

import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.opensearch.common.Strings;
import org.opensearch.common.settings.Settings;

import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.PemKeyReader;

public class WebhookSink extends AuditLogSink {

	/* HttpClient is thread safe */
	private final CloseableHttpClient httpClient;

	String webhookUrl = null;
	WebhookFormat webhookFormat = null;
	final boolean verifySSL;
	final KeyStore effectiveTruststore;

    public WebhookSink(final String name, final Settings settings, final String settingsPrefix, final Path configPath, AuditLogSink fallbackSink) throws Exception {
	    super(name, settings, settingsPrefix, fallbackSink);

	    Settings sinkSettings = settings.getAsSettings(settingsPrefix);

	    this.effectiveTruststore = getEffectiveKeyStore(configPath);

		final String webhookUrl = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_WEBHOOK_URL);
		final String format = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_WEBHOOK_FORMAT);

		verifySSL = sinkSettings.getAsBoolean(ConfigConstants.SECURITY_AUDIT_WEBHOOK_SSL_VERIFY, true);
		httpClient = getHttpClient();

		if(httpClient == null) {
			log.error("Could not create HttpClient, audit log not available.");
			return;
		}

		if (Strings.isEmpty(webhookUrl)) {
			log.error("plugins.security.audit.config.webhook.url not provided, webhook audit log will not work");
			return;
		} else {
			try {
				// Sanity - check URL validity
				new URL(webhookUrl);
				this.webhookUrl = webhookUrl;
			} catch (MalformedURLException ex) {
				log.error("URL {} is invalid, webhook audit log will not work.", webhookUrl, ex);
			}
		}

		if (Strings.isEmpty(format)) {
			log.warn("plugins.security.audit.config.webhook.format not provided, falling back to 'text'");
			webhookFormat = WebhookFormat.TEXT;
		} else {
			try {
				webhookFormat = WebhookFormat.valueOf(format.toUpperCase());
			} catch (Exception ex) {
				log.error("Could not find WebhookFormat for type {}, falling back to 'text'", format, ex);
				webhookFormat = WebhookFormat.TEXT;
			}
		}
	}

	@Override
	public boolean doStore(AuditMessage msg) {
		if (Strings.isEmpty(webhookUrl)) {
			log.debug("Webhook URL is null");
			return false;
		}
		if (msg == null) {
			log.debug("Message is null");
			return true;
		}

		return AccessController.doPrivileged(new PrivilegedAction<Boolean>() {

			@Override
			public Boolean run() {
				boolean success = false;
				try {
					switch (webhookFormat.method) {
					case POST:
						success = post(msg);
						break;
					case GET:
						 success =get(msg);
						break;
					default:
						log.error("Http Method '{}' defined in WebhookFormat '{}' not implemented yet", webhookFormat.method.name(),
								webhookFormat.name());
					}
					// log something in case endpoint is not reachable or did not return 200
					if (!success) {
						log.error(msg.toString());
					}
					return success;
				} catch(Throwable t) {
					log.error("Uncaught exception while trying to log message.", t);
					log.error(msg.toString());
					return false;
				}
			}
		});
	}

    @Override
    public void close() throws IOException {
        if(httpClient != null) {
        	httpClient.close();
        }
    }


	/**
	 * Transforms an {@link AuditMessage} to JSON. By default, all fields are
	 * included in the JSON string. This method can be overridden by subclasses
	 * if a specific JSON format is needed.
	 *
	 * @param msg the AuditMessage to transform
	 * @return the JSON string
	 */
	protected String formatJson(final AuditMessage msg) {
		return msg.toJson();
	}

	/**
	 * Transforms an {@link AuditMessage} to plain text. This method can be overridden
	 * by subclasses if a specific text format is needed.
	 *
	 * @param msg the AuditMessage to transform
	 * @return the text string
	 */
	protected String formatText(AuditMessage msg) {
		return msg.toText();
	}

	/**
	 * Transforms an {@link AuditMessage} to Slack format.
	 * The default implementation returns
	 * <p><blockquote><pre>
	 * {
	 *   "text": "<AuditMessage#toText>"
	 * }
	 * </pre></blockquote>
	 * <p>
	 * Can be overridden by subclasses if a more specific format is needed.
	 *
	 * @param msg the AuditMessage to transform
	 * @return the Slack formatted JSON string
	 */
	protected String formatSlack(AuditMessage msg) {
		return "{\"text\": \"" + msg.toText() + "\"}";
	}

	/**
	 * Transforms an {@link AuditMessage} to a query parameter String.
	 * Used by {@link WebhookFormat#URL_PARAMETER_GET} and
	 * Used by {@link WebhookFormat#URL_PARAMETER_POST}. Can be overridden by
	 * subclasses if a specific format is needed.
	 *
	 * @param msg the AuditMessage to transform
	 * @return the query parameter string
	 */
	protected String formatUrlParameters(AuditMessage msg) {
		return msg.toUrlParameters();
	}

	boolean get(AuditMessage msg) {
		switch (webhookFormat) {
		case URL_PARAMETER_GET:
			return doGet(webhookUrl + formatUrlParameters(msg));
		default:
			log.error("WebhookFormat '{}' not implemented yet", webhookFormat.name());
			return false;
		}
	}

	protected boolean doGet(String url) {
		HttpGet httpGet = new HttpGet(url);
		CloseableHttpResponse serverResponse = null;
		try {
			serverResponse = httpClient.execute(httpGet);
			int responseCode = serverResponse.getStatusLine().getStatusCode();
			if (responseCode != HttpStatus.SC_OK) {
				log.error("Cannot GET to webhook URL '{}', server returned status {}", webhookUrl, responseCode);
				return false;
			}
			return true;
		} catch (Throwable e) {
			log.error("Cannot GET to webhook URL '{}'", webhookUrl, e);
			return false;
		} finally {
			try {
				if (serverResponse != null) {
					serverResponse.close();
				}
			} catch (IOException e) {
				log.error("Cannot close server response", e);
			}
		}
	}

	boolean post(AuditMessage msg) {

		String payload;
		String url = webhookUrl;

		switch (webhookFormat) {
		case JSON:
			payload = formatJson(msg);
			break;
		case TEXT:
			payload = formatText(msg);
			break;
		case SLACK:
			payload = "{\"text\": \"" + msg.toText() + "\"}";
			break;
		case URL_PARAMETER_POST:
			payload = "";
			url = webhookUrl + formatUrlParameters(msg);
			break;
		default:
			log.error("WebhookFormat '{}' not implemented yet", webhookFormat.name());
			return false;
		}

		return doPost(url, payload);

	}

	protected boolean doPost(String url, String payload) {

		HttpPost postRequest = new HttpPost(url);

		StringEntity input = new StringEntity(payload, StandardCharsets.UTF_8);
		input.setContentType(webhookFormat.contentType.toString());
		postRequest.setEntity(input);

		CloseableHttpResponse serverResponse = null;
		try {
			serverResponse = httpClient.execute(postRequest);
			int responseCode = serverResponse.getStatusLine().getStatusCode();
			if (responseCode != HttpStatus.SC_OK) {
				log.error("Cannot POST to webhook URL '{}', server returned status {}", webhookUrl, responseCode);
				return false;
			}
			return true;
		} catch (Throwable e) {
			log.error("Cannot POST to webhook URL '{}' due to '{}'", webhookUrl, e.getMessage(), e);
			return false;
		} finally {
			try {
				if (serverResponse != null) {
					serverResponse.close();
				}
			} catch (IOException e) {
				log.error("Cannot close server response", e);
			}
		}
	}

	private KeyStore getEffectiveKeyStore(final Path configPath) {

		return AccessController.doPrivileged(new PrivilegedAction<KeyStore>() {

			@Override
			public KeyStore run() {
				try {
					Settings sinkSettings = settings.getAsSettings(settingsPrefix);

					final boolean pem = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH, null) != null
			                || sinkSettings.get(ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT, null) != null;

					if(pem) {
					    X509Certificate[] trustCertificates = PemKeyReader.loadCertificatesFromStream(PemKeyReader.resolveStream(ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT, sinkSettings));

			            if(trustCertificates == null) {
			            	String fullPath = settingsPrefix + "." + ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH;
			                trustCertificates = PemKeyReader.loadCertificatesFromFile(PemKeyReader.resolve(fullPath, settings, configPath, false));
			            }

			            return PemKeyReader.toTruststore("alw", trustCertificates);


					} else {
					    return PemKeyReader.loadKeyStore(PemKeyReader.resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, settings, configPath, false)
			                    , settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, SSLConfigConstants.DEFAULT_STORE_PASSWORD)
			                    , settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE));
					}
				} catch(Exception ex) {
					log.error("Could not load key material. Make sure your certificates are located relative to the config directory", ex);
					return null;
				}
			}
		});
	}

	CloseableHttpClient getHttpClient()  {

        // TODO: set a timeout until we have a proper way to deal with back pressure
        int timeout = 5;

        RequestConfig config = RequestConfig.custom()
          .setConnectTimeout(timeout * 1000)
          .setConnectionRequestTimeout(timeout * 1000)
          .setSocketTimeout(timeout * 1000).build();

        final TrustStrategy trustAllStrategy = new TrustStrategy() {
            @Override
            public boolean isTrusted(X509Certificate[] chain, String authType) {
                return true;
            }
        };

	    try {

	        if(!verifySSL) {
	            return HttpClients.custom()
	                    .setSSLSocketFactory(
	                            new SSLConnectionSocketFactory(
	                                    new SSLContextBuilder()
	                                    .loadTrustMaterial(trustAllStrategy)
	                                    .build(),
	                                    NoopHostnameVerifier.INSTANCE))
	                    .setDefaultRequestConfig(config)
	                    .build();
	        }

	        if(effectiveTruststore == null) {
	            return HttpClients.custom()
                        .setDefaultRequestConfig(config)
                        .build();
	        }

		    return HttpClients.custom()
		            .setSSLSocketFactory(
		                    new SSLConnectionSocketFactory(
		                            new SSLContextBuilder()
		                            .loadTrustMaterial(effectiveTruststore, null)
		                            .build(),
		                            new DefaultHostnameVerifier()))
		            .setDefaultRequestConfig(config)
		            .build();


	    } catch(Exception ex) {
	    	log.error("Could not create HTTPClient due to {}, audit log not available.", ex.getMessage(), ex);
	    	return null;
	    }
	}

	public static enum WebhookFormat {
		URL_PARAMETER_GET(HttpMethod.GET, ContentType.TEXT_PLAIN),
		URL_PARAMETER_POST(HttpMethod.POST, ContentType.TEXT_PLAIN),
		TEXT(HttpMethod.POST, ContentType.TEXT_PLAIN),
		JSON(HttpMethod.POST, ContentType.APPLICATION_JSON),
		SLACK(HttpMethod.POST, ContentType.APPLICATION_JSON);

		private HttpMethod method;
		private ContentType contentType;

		private WebhookFormat(HttpMethod method, ContentType contentType) {
			this.method = method;
			this.contentType = contentType;
		}

		HttpMethod getMethod() {
			return method;
		}

		ContentType getContentType() {
			return contentType;
		}


	}

	private static enum HttpMethod {
		GET,
		POST;
	}


}
