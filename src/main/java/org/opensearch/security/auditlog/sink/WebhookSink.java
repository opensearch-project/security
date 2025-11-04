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

package org.opensearch.security.auditlog.sink;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.reactor.ssl.SSLBufferMode;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.http.HttpStatus;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.Strings;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.PemKeyReader;

import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD;

public class WebhookSink extends AuditLogSink {

    /* HttpClient is thread safe */
    private final CloseableHttpClient httpClient;

    String webhookUrl = null;
    WebhookFormat webhookFormat = null;
    final boolean verifySSL;
    final KeyStore effectiveTruststore;

    public WebhookSink(
        final String name,
        final Settings settings,
        final String settingsPrefix,
        final Path configPath,
        AuditLogSink fallbackSink
    ) throws Exception {
        super(name, settings, settingsPrefix, fallbackSink);

        Settings sinkSettings = settings.getAsSettings(settingsPrefix);

        this.effectiveTruststore = getEffectiveKeyStore(configPath);

        final String webhookUrl = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_WEBHOOK_URL);
        final String format = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_WEBHOOK_FORMAT);

        verifySSL = sinkSettings.getAsBoolean(ConfigConstants.SECURITY_AUDIT_WEBHOOK_SSL_VERIFY, true);
        httpClient = getHttpClient();

        if (httpClient == null) {
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

        return AccessController.doPrivileged(() -> {
            boolean success = false;
            try {
                switch (webhookFormat.method) {
                    case POST:
                        success = post(msg);
                        break;
                    case GET:
                        success = get(msg);
                        break;
                    default:
                        log.error(
                            "Http Method '{}' defined in WebhookFormat '{}' not implemented yet",
                            webhookFormat.method.name(),
                            webhookFormat.name()
                        );
                }
                // log something in case endpoint is not reachable or did not return 200
                if (!success) {
                    log.error(msg.toString());
                }
                return success;
            } catch (Throwable t) {
                log.error("Uncaught exception while trying to log message.", t);
                log.error(msg.toString());
                return false;
            }
        });
    }

    @Override
    public void close() throws IOException {
        if (httpClient != null) {
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
            int responseCode = serverResponse.getCode();
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

        StringEntity input = new StringEntity(payload, webhookFormat.contentType.withCharset(StandardCharsets.UTF_8));
        postRequest.setEntity(input);

        CloseableHttpResponse serverResponse = null;
        try {
            serverResponse = httpClient.execute(postRequest);
            int responseCode = serverResponse.getCode();
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

        return AccessController.doPrivileged(() -> {
            try {
                Settings sinkSettings = settings.getAsSettings(settingsPrefix);

                final boolean pem = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH, null) != null
                    || sinkSettings.get(ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT, null) != null;

                if (pem) {
                    X509Certificate[] trustCertificates = PemKeyReader.loadCertificatesFromStream(
                        PemKeyReader.resolveStream(ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT, sinkSettings)
                    );

                    if (trustCertificates == null) {
                        String fullPath = settingsPrefix + "." + ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH;
                        trustCertificates = PemKeyReader.loadCertificatesFromFile(
                            PemKeyReader.resolve(fullPath, settings, configPath, false)
                        );
                    }

                    return PemKeyReader.toTruststore("alw", trustCertificates);

                } else {
                    return PemKeyReader.loadKeyStore(
                        PemKeyReader.resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, settings, configPath, false),
                        SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD.getSetting(settings),
                        settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE)
                    );
                }
            } catch (Exception ex) {
                log.error("Could not load key material. Make sure your certificates are located relative to the config directory", ex);
                return null;
            }
        });
    }

    CloseableHttpClient getHttpClient() {

        // TODO: set a timeout until we have a proper way to deal with back pressure
        int timeout = 5;

        RequestConfig config = RequestConfig.custom()
            .setConnectTimeout(timeout, TimeUnit.SECONDS)
            .setConnectionRequestTimeout(timeout, TimeUnit.SECONDS)
            .build();

        try {
            HttpClientBuilder hcb = HttpClients.custom().setDefaultRequestConfig(config);
            if (!verifySSL) {
                SSLContext sslContext = SSLContextBuilder.create().loadTrustMaterial(TrustAllStrategy.INSTANCE).build();
                final DefaultClientTlsStrategy sslsf = new DefaultClientTlsStrategy(
                    sslContext,
                    null,
                    null,
                    SSLBufferMode.STATIC,
                    NoopHostnameVerifier.INSTANCE
                );

                final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
                    .setTlsSocketStrategy(sslsf)
                    .setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(timeout, TimeUnit.SECONDS).build())
                    .build();
                hcb.setConnectionManager(cm);
                return hcb.build();
            }

            if (effectiveTruststore == null) {
                return HttpClients.custom().setDefaultRequestConfig(config).build();
            }
            SSLContext sslContext = SSLContextBuilder.create().loadTrustMaterial(effectiveTruststore, null).build();
            final DefaultClientTlsStrategy sslsf = new DefaultClientTlsStrategy(
                sslContext,
                null,
                null,
                SSLBufferMode.STATIC,
                new DefaultHostnameVerifier()
            );

            final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
                .setTlsSocketStrategy(sslsf)
                .setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(timeout, TimeUnit.SECONDS).build())
                .build();
            hcb.setConnectionManager(cm);

            return hcb.build();

        } catch (Exception ex) {
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
