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

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.elasticsearch.common.settings.Settings;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.httpclient.HttpClient;
import com.amazon.opendistroforelasticsearch.security.httpclient.HttpClient.HttpClientBuilder;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.PemKeyReader;

public final class ExternalESSink extends AuditLogSink {

    private static final List<String> DEFAULT_TLS_PROTOCOLS = Arrays.asList(new String[] { "TLSv1.2", "TLSv1.1"});
	// config in elasticsearch.yml
	private final String index;
	private final String type;
	private final HttpClient client;
	private List<String> servers;
	private DateTimeFormatter indexPattern;

    static final String PKCS12 = "PKCS12";

	public ExternalESSink(final String name, final Settings settings, final String settingPrefix, final Path configPath, AuditLogSink fallbackSink) throws Exception {

		super(name, settings, settingPrefix, fallbackSink);
		Settings sinkSettings = settings.getAsSettings(settingPrefix);
		servers = sinkSettings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_HTTP_ENDPOINTS);
		if (servers == null || servers.size() == 0) {
			log.error("No http endpoints configured for external Elasticsearch endpoint '{}', falling back to localhost.", name);
			servers = Collections.singletonList("localhost:9200");
		}

		this.index = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ES_INDEX, "'security-auditlog-'YYYY.MM.dd");

		try {
            this.indexPattern = DateTimeFormat.forPattern(index);
        } catch (IllegalArgumentException e) {
            log.debug("Unable to parse index pattern due to {}. "
                    + "If you have no date pattern configured you can safely ignore this message", e.getMessage());
        }

		this.type = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ES_TYPE, null);
		final boolean verifyHostnames = sinkSettings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_VERIFY_HOSTNAMES, true);
		final boolean enableSsl = sinkSettings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL, false);
		final boolean enableSslClientAuth = sinkSettings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL_CLIENT_AUTH , ConfigConstants.OPENDISTRO_SECURITY_AUDIT_SSL_ENABLE_SSL_CLIENT_AUTH_DEFAULT);
		final String user = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_USERNAME);
		final String password = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PASSWORD);

		final HttpClientBuilder builder = HttpClient.builder(servers.toArray(new String[0]));

		if (enableSsl) {

		    final boolean pem = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_FILEPATH, null) != null
                    || sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_CONTENT, null) != null;

		    KeyStore effectiveTruststore;
		    KeyStore effectiveKeystore;
		    char[] effectiveKeyPassword;
		    String effectiveKeyAlias;

		    final boolean isDebugEnabled = log.isDebugEnabled();

		    if(pem) {
                X509Certificate[] trustCertificates = PemKeyReader.loadCertificatesFromStream(PemKeyReader.resolveStream(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_CONTENT, sinkSettings));

                if(trustCertificates == null) {
                	String path = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_FILEPATH);
                    trustCertificates = PemKeyReader.loadCertificatesFromFile(PemKeyReader.resolve(path, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_FILEPATH, settings, configPath, true));
                }

                //for client authentication
                X509Certificate[] authenticationCertificate = PemKeyReader.loadCertificatesFromStream(PemKeyReader.resolveStream(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMCERT_CONTENT, sinkSettings));

                if(authenticationCertificate == null) {
                	String path = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMCERT_FILEPATH);
                    authenticationCertificate = PemKeyReader.loadCertificatesFromFile(PemKeyReader.resolve(path, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMCERT_FILEPATH, settings, configPath, enableSslClientAuth));
                }

                PrivateKey authenticationKey = PemKeyReader.loadKeyFromStream(sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_PASSWORD), PemKeyReader.resolveStream(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_CONTENT, sinkSettings));

                if(authenticationKey == null) {
                	String path = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_FILEPATH);
                    authenticationKey = PemKeyReader.loadKeyFromFile(sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_PASSWORD), PemKeyReader.resolve(path, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_FILEPATH, settings, configPath, enableSslClientAuth));
                }

                effectiveKeyPassword = PemKeyReader.randomChars(12);
                effectiveKeyAlias = "al";
                effectiveTruststore = PemKeyReader.toTruststore(effectiveKeyAlias, trustCertificates);
                effectiveKeystore = PemKeyReader.toKeystore(effectiveKeyAlias, effectiveKeyPassword, authenticationCertificate, authenticationKey);

                if (isDebugEnabled) {
                    log.debug("Use PEM to secure communication with auditlog server (client auth is {})", authenticationKey!=null);
                }

            } else {
                final KeyStore trustStore = PemKeyReader.loadKeyStore(PemKeyReader.resolve(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, settings, configPath, true)
                        , settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, SSLConfigConstants.DEFAULT_STORE_PASSWORD)
                        , settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE));

                //for client authentication
                final KeyStore keyStore = PemKeyReader.loadKeyStore(PemKeyReader.resolve(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, settings, configPath, enableSslClientAuth)
                        , settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD, SSLConfigConstants.DEFAULT_STORE_PASSWORD)
                        , settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE));
                final String keyStorePassword = settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD, SSLConfigConstants.DEFAULT_STORE_PASSWORD);
                effectiveKeyPassword = keyStorePassword==null||keyStorePassword.isEmpty()?null:keyStorePassword.toCharArray();
                effectiveKeyAlias = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_JKS_CERT_ALIAS, null);

                if(enableSslClientAuth && effectiveKeyAlias == null) {
                    throw new IllegalArgumentException(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_JKS_CERT_ALIAS+" not given");
                }

                effectiveTruststore = trustStore;
                effectiveKeystore = keyStore;

                if (isDebugEnabled) {
                    log.debug("Use Trust-/Keystore to secure communication with LDAP server (client auth is {})", keyStore!=null);
                    log.debug("keyStoreAlias: {}",  effectiveKeyAlias);
                }

            }

		    final List<String> enabledCipherSuites = sinkSettings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLED_SSL_CIPHERS, null);
            final List<String> enabledProtocols = sinkSettings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLED_SSL_PROTOCOLS, DEFAULT_TLS_PROTOCOLS);

            builder.setSupportedCipherSuites(enabledCipherSuites==null?null:enabledCipherSuites.toArray(new String[0]));
            builder.setSupportedProtocols(enabledProtocols.toArray(new String[0]));

            builder.enableSsl(effectiveTruststore, verifyHostnames); //trust all aliases

            if (enableSslClientAuth) {
                builder.setPkiCredentials(effectiveKeystore, effectiveKeyPassword, effectiveKeyAlias);
            }
		}

		if (user != null && password != null) {
			builder.setBasicCredentials(user, password);
		}

		client = builder.build();
	}

	@Override
	public void close() throws IOException {
		if (client != null) {
			client.close();
		}
	}

	public boolean doStore(final AuditMessage msg) {
		try {
			boolean successful = client.index(msg.toString(), getExpandedIndexName(indexPattern, index), type, true);
			if (!successful) {
				log.error("Unable to send audit log {} to one of these servers: {}", msg, servers);
			}
			return successful;
		} catch (Exception e) {
			log.error("Unable to send audit log {} due to", msg, e);
			return false;
		}
	}
}
