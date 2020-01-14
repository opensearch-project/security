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

package com.amazon.opendistroforelasticsearch.security.ssl;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;

import com.amazon.opendistroforelasticsearch.security.ssl.util.ExceptionUtils;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLCertificateHelper;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;

public class DefaultOpenDistroSecurityKeyStore implements OpenDistroSecurityKeyStore {

    private static final String DEFAULT_STORE_TYPE = "JKS";

    private void printJCEWarnings() {
        try {
            final int aesMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");

            if (aesMaxKeyLength < 256) {
                log.info("AES-256 not supported, max key length for AES is " + aesMaxKeyLength + " bit."
                        + " (This is not an issue, it just limits possible encryption strength. To enable AES 256, install 'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files')");
            }
        } catch (final NoSuchAlgorithmException e) {
            log.error("AES encryption not supported (SG 1). " + e);
        }
    }

    private final Settings settings;
    private final Logger log = LogManager.getLogger(this.getClass());
    public final SslProvider sslHTTPProvider;
    public final SslProvider sslTransportServerProvider;
    public final SslProvider sslTransportClientProvider;
    private final boolean httpSSLEnabled;
    private final boolean transportSSLEnabled;
    
    private List<String> enabledHttpCiphersJDKProvider;
    private List<String> enabledHttpCiphersOpenSSLProvider;
    private List<String> enabledTransportCiphersJDKProvider;
    private List<String> enabledTransportCiphersOpenSSLProvider;
    
    private List<String> enabledHttpProtocolsJDKProvider;
    private List<String> enabledHttpProtocolsOpenSSLProvider;
    private List<String> enabledTransportProtocolsJDKProvider;
    private List<String> enabledTransportProtocolsOpenSSLProvider;
    
    private SslContext httpSslContext;
    private SslContext transportServerSslContext;
    private SslContext transportClientSslContext;
    private final Environment env;

    public DefaultOpenDistroSecurityKeyStore(final Settings settings, final Path configPath) {
        super();
        this.settings = settings;
        Environment _env;
        try {
            _env = new Environment(settings, configPath);
        } catch (IllegalStateException e) {
            _env = null;
        }
        env = _env;
        httpSSLEnabled = settings.getAsBoolean(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED,
                SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED_DEFAULT);
        transportSSLEnabled = settings.getAsBoolean(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED,
                SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT);
        final boolean useOpenSSLForHttpIfAvailable = OpenDistroSecuritySSLPlugin.OPENSSL_SUPPORTED && settings
                .getAsBoolean(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, true);
        final boolean useOpenSSLForTransportIfAvailable = OpenDistroSecuritySSLPlugin.OPENSSL_SUPPORTED && settings
                .getAsBoolean(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, true);

        if(!OpenDistroSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable() && (settings.getAsBoolean(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, true) || settings.getAsBoolean(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, true) )) {
            String text = "Support for OpenSSL with Java 12+ has been removed from Open Distro Security since Elasticsearch 7.4.0. Using JDK SSL instead.\n";
            System.out.println(text);
            log.warn(text);
        }

        boolean openSSLInfoLogged = false;

        if (httpSSLEnabled && useOpenSSLForHttpIfAvailable) {
            sslHTTPProvider = SslContext.defaultServerProvider();
            logOpenSSLInfos();
            openSSLInfoLogged = true;
        } else if (httpSSLEnabled) {
            sslHTTPProvider = SslProvider.JDK;
        } else {
            sslHTTPProvider = null;
        }

        if (transportSSLEnabled && useOpenSSLForTransportIfAvailable) {
            sslTransportClientProvider = SslContext.defaultClientProvider();
            sslTransportServerProvider = SslContext.defaultServerProvider();
            if (!openSSLInfoLogged) {
                logOpenSSLInfos();
            }
        } else if (transportSSLEnabled) {
            sslTransportClientProvider = sslTransportServerProvider = SslProvider.JDK;
        } else {
            sslTransportClientProvider = sslTransportServerProvider = null;
        }

        initEnabledSSLCiphers();
        initSSLConfig();
        printJCEWarnings();

        log.info("TLS Transport Client Provider : {}", sslTransportClientProvider);
        log.info("TLS Transport Server Provider : {}", sslTransportServerProvider);
        log.info("TLS HTTP Provider             : {}", sslHTTPProvider);

        log.debug("sslTransportClientProvider:{} with ciphers {}", sslTransportClientProvider,
                getEnabledSSLCiphers(sslTransportClientProvider, false));
        log.debug("sslTransportServerProvider:{} with ciphers {}", sslTransportServerProvider,
                getEnabledSSLCiphers(sslTransportServerProvider, false));
        log.debug("sslHTTPProvider:{} with ciphers {}", sslHTTPProvider, getEnabledSSLCiphers(sslHTTPProvider, true));

        log.info("Enabled TLS protocols for transport layer : {}",
                Arrays.toString(getEnabledSSLProtocols(sslTransportServerProvider, false)));
        log.info("Enabled TLS protocols for HTTP layer      : {}",
                Arrays.toString(getEnabledSSLProtocols(sslHTTPProvider, true)));
        
        
        log.debug("sslTransportClientProvider:{} with protocols {}", sslTransportClientProvider,
                getEnabledSSLProtocols(sslTransportClientProvider, false));
        log.debug("sslTransportServerProvider:{} with protocols {}", sslTransportServerProvider,
                getEnabledSSLProtocols(sslTransportServerProvider, false));
        log.debug("sslHTTPProvider:{} with protocols {}", sslHTTPProvider, getEnabledSSLProtocols(sslHTTPProvider, true));

        if (transportSSLEnabled && (getEnabledSSLCiphers(sslTransportClientProvider, false).isEmpty()
                || getEnabledSSLCiphers(sslTransportServerProvider, false).isEmpty())) {
            throw new ElasticsearchSecurityException("no valid cipher suites for transport protocol");
        }

        if (httpSSLEnabled && getEnabledSSLCiphers(sslHTTPProvider, true).isEmpty()) {
            throw new ElasticsearchSecurityException("no valid cipher suites for https");
        }

        if (transportSSLEnabled && getEnabledSSLCiphers(sslTransportServerProvider, false).isEmpty()) {
            throw new ElasticsearchSecurityException("no ssl protocols for transport protocol");
        }
        
        if (transportSSLEnabled && getEnabledSSLCiphers(sslTransportClientProvider, false).isEmpty()) {
            throw new ElasticsearchSecurityException("no ssl protocols for transport protocol");
        }

        if (httpSSLEnabled && getEnabledSSLCiphers(sslHTTPProvider, true).isEmpty()) {
            throw new ElasticsearchSecurityException("no ssl protocols for https");
        }
    }

    private String resolve(String propName, boolean mustBeValid) {

        final String originalPath = settings.get(propName, null);
        String path = originalPath;
        log.debug("Value for {} is {}", propName, originalPath);

        if (env != null && originalPath != null && originalPath.length() > 0) {
            path = env.configFile().resolve(originalPath).toAbsolutePath().toString();
            log.debug("Resolved {} to {} against {}", originalPath, path, env.configFile().toAbsolutePath().toString());
        }

        if (mustBeValid) {
            checkPath(path, propName);
        }

        if ("".equals(path)) {
            path = null;
        }

        return path;
    }

    private void initSSLConfig() {

        if (env == null) {
            log.info("No config directory, key- and truststore files are resolved absolutely");
        } else {
            log.info("Config directory is {}/, from there the key- and truststore files are resolved relatively",
                    env.configFile().toAbsolutePath());
        }

        if (transportSSLEnabled) {

            final String rawKeyStoreFilePath = settings
                    .get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, null);
            final String rawPemCertFilePath = settings
                    .get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, null);

            if (rawKeyStoreFilePath != null) {

                final String keystoreFilePath = resolve(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                        true);
                final String keystoreType = settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE,
                        DEFAULT_STORE_TYPE);
                final String keystorePassword = settings.get(
                        SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD,
                        SSLConfigConstants.DEFAULT_STORE_PASSWORD);
                
                final String keyPassword = settings.get(
                        SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD,
                        keystorePassword);
                
                final String keystoreAlias = settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS,
                        null);

                final String truststoreFilePath = resolve(
                        SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, true);

                if (settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, null) == null) {
                    throw new ElasticsearchException(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH
                            + " must be set if transport ssl is requested.");
                }

                final String truststoreType = settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE,
                        DEFAULT_STORE_TYPE);
                final String truststorePassword = settings.get(
                        SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD,
                        SSLConfigConstants.DEFAULT_STORE_PASSWORD);
                final String truststoreAlias = settings
                        .get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS, null);

                try {

                    final KeyStore ks = KeyStore.getInstance(keystoreType);
                    ks.load(new FileInputStream(new File(keystoreFilePath)),
                            (keystorePassword == null || keystorePassword.length() == 0) ? null
                                    : keystorePassword.toCharArray());

                    final X509Certificate[] transportKeystoreCert = SSLCertificateHelper.exportServerCertChain(ks,
                            keystoreAlias);
                    final PrivateKey transportKeystoreKey = SSLCertificateHelper.exportDecryptedKey(ks, keystoreAlias,
                            (keyPassword == null || keyPassword.length() == 0) ? null
                                    : keyPassword.toCharArray());

                    if (transportKeystoreKey == null) {
                        throw new ElasticsearchException(
                                "No key found in " + keystoreFilePath + " with alias " + keystoreAlias);
                    }

                    if (transportKeystoreCert != null && transportKeystoreCert.length > 0) {

                        // TODO create sensitive log property
                        /*
                         * for (int i = 0; i < transportKeystoreCert.length; i++) { X509Certificate
                         * x509Certificate = transportKeystoreCert[i];
                         * 
                         * if(x509Certificate != null) {
                         * log.info("Transport keystore subject DN no. {} {}",i,x509Certificate.
                         * getSubjectX500Principal()); } }
                         */
                    } else {
                        throw new ElasticsearchException(
                                "No certificates found in " + keystoreFilePath + " with alias " + keystoreAlias);
                    }

                    final KeyStore ts = KeyStore.getInstance(truststoreType);
                    ts.load(new FileInputStream(new File(truststoreFilePath)),
                            (truststorePassword == null || truststorePassword.length() == 0) ? null
                                    : truststorePassword.toCharArray());

                    final X509Certificate[] trustedTransportCertificates = SSLCertificateHelper
                            .exportRootCertificates(ts, truststoreAlias);

                    if (trustedTransportCertificates == null) {
                        throw new ElasticsearchException("No truststore configured for server");
                    }

                    transportServerSslContext = buildSSLServerContext(transportKeystoreKey, transportKeystoreCert,
                            trustedTransportCertificates, getEnabledSSLCiphers(this.sslTransportServerProvider, false),
                            this.sslTransportServerProvider, ClientAuth.REQUIRE);
                    transportClientSslContext = buildSSLClientContext(transportKeystoreKey, transportKeystoreCert,
                            trustedTransportCertificates, getEnabledSSLCiphers(sslTransportClientProvider, false),
                            sslTransportClientProvider);

                } catch (final Exception e) {
                    logExplanation(e);
                    throw new ElasticsearchSecurityException(
                            "Error while initializing transport SSL layer: " + e.toString(), e);
                }

            } else if (rawPemCertFilePath != null) {

                final String pemCertFilePath = resolve(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH,
                        true);
                final String pemKey = resolve(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, true);
                final String trustedCas = resolve(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH,
                        true);

                try {

                    transportServerSslContext = buildSSLServerContext(new File(pemKey), new File(pemCertFilePath),
                            new File(trustedCas),
                            settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD),
                            getEnabledSSLCiphers(this.sslTransportServerProvider, false),
                            this.sslTransportServerProvider, ClientAuth.REQUIRE);
                    transportClientSslContext = buildSSLClientContext(new File(pemKey), new File(pemCertFilePath),
                            new File(trustedCas),
                            settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD),
                            getEnabledSSLCiphers(sslTransportClientProvider, false), sslTransportClientProvider);

                } catch (final Exception e) {
                    logExplanation(e);
                    throw new ElasticsearchSecurityException(
                            "Error while initializing transport SSL layer from PEM: " + e.toString(), e);
                }

            } else {
                throw new ElasticsearchException(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH + " or "
                        + SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH
                        + " must be set if transport ssl is reqested.");
            }
        }

        final boolean client = !"node".equals(this.settings.get(OpenDistroSecuritySSLPlugin.CLIENT_TYPE));

        if (!client && httpSSLEnabled) {

            final String rawKeystoreFilePath = settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                    null);
            final String rawPemCertFilePath = settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMCERT_FILEPATH,
                    null);
            final ClientAuth httpClientAuthMode = ClientAuth.valueOf(settings
                    .get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, ClientAuth.OPTIONAL.toString()));

            if (rawKeystoreFilePath != null) {

                final String keystoreFilePath = resolve(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                        true);
                final String keystoreType = settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_TYPE,
                        DEFAULT_STORE_TYPE);
                final String keystorePassword = settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD,
                        SSLConfigConstants.DEFAULT_STORE_PASSWORD);
                
                final String keyPassword = settings.get(
                        SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD,
                        keystorePassword);
                
                
                final String keystoreAlias = settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_ALIAS, null);

                log.info("HTTPS client auth mode {}", httpClientAuthMode);

                if (settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, null) == null) {
                    throw new ElasticsearchException(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH
                            + " must be set if https is reqested.");
                }

                if (httpClientAuthMode == ClientAuth.REQUIRE) {

                    if (settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, null) == null) {
                        throw new ElasticsearchException(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH
                                + " must be set if http ssl and client auth is reqested.");
                    }

                }

                try {

                    final KeyStore ks = KeyStore.getInstance(keystoreType);
                    try (FileInputStream fin = new FileInputStream(new File(keystoreFilePath))) {
                        ks.load(fin, (keystorePassword == null || keystorePassword.length() == 0) ? null
                                : keystorePassword.toCharArray());
                    }

                    final X509Certificate[] httpKeystoreCert = SSLCertificateHelper.exportServerCertChain(ks,
                            keystoreAlias);
                    final PrivateKey httpKeystoreKey = SSLCertificateHelper.exportDecryptedKey(ks, keystoreAlias,
                            (keyPassword == null || keyPassword.length() == 0) ? null
                                    : keyPassword.toCharArray());

                    if (httpKeystoreKey == null) {
                        throw new ElasticsearchException(
                                "No key found in " + keystoreFilePath + " with alias " + keystoreAlias);
                    }

                    if (httpKeystoreCert != null && httpKeystoreCert.length > 0) {

                        // TODO create sensitive log property
                        /*
                         * for (int i = 0; i < httpKeystoreCert.length; i++) { X509Certificate
                         * x509Certificate = httpKeystoreCert[i];
                         * 
                         * if(x509Certificate != null) {
                         * log.info("HTTP keystore subject DN no. {} {}",i,x509Certificate.
                         * getSubjectX500Principal()); } }
                         */
                    } else {
                        throw new ElasticsearchException(
                                "No certificates found in " + keystoreFilePath + " with alias " + keystoreAlias);
                    }

                    X509Certificate[] trustedHTTPCertificates = null;

                    if (settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, null) != null) {

                        final String truststoreFilePath = resolve(
                                SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, true);

                        final String truststoreType = settings
                                .get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, DEFAULT_STORE_TYPE);
                        final String truststorePassword = settings.get(
                                SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD,
                                SSLConfigConstants.DEFAULT_STORE_PASSWORD);
                        final String truststoreAlias = settings
                                .get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS, null);

                        final KeyStore ts = KeyStore.getInstance(truststoreType);
                        try (FileInputStream fin = new FileInputStream(new File(truststoreFilePath))) {
                            ts.load(fin, (truststorePassword == null || truststorePassword.length() == 0) ? null
                                    : truststorePassword.toCharArray());
                        }
                        trustedHTTPCertificates = SSLCertificateHelper.exportRootCertificates(ts, truststoreAlias);
                    }

                    httpSslContext = buildSSLServerContext(httpKeystoreKey, httpKeystoreCert, trustedHTTPCertificates,
                            getEnabledSSLCiphers(this.sslHTTPProvider, true), sslHTTPProvider, httpClientAuthMode);

                } catch (final Exception e) {
                    logExplanation(e);
                    throw new ElasticsearchSecurityException("Error while initializing HTTP SSL layer: " + e.toString(),
                            e);
                }

            } else if (rawPemCertFilePath != null) {

                final String trustedCas = resolve(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH,
                        false);

                if (httpClientAuthMode == ClientAuth.REQUIRE) {

                    // if(trustedCas == null ||
                    // trustedCas.equals(env.config-File().toAbsolutePath().toString())) {
                    // throw new
                    // ElasticsearchException(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH
                    // + " must be set if http ssl and client auth is reqested.");
                    // }

                    checkPath(trustedCas, SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH);

                }

                final String pemCertFilePath = resolve(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, true);
                final String pemKey = resolve(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_FILEPATH, true);

                try {
                    httpSslContext = buildSSLServerContext(new File(pemKey), new File(pemCertFilePath),
                            trustedCas == null ? null : new File(trustedCas),
                            settings.get(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_PASSWORD),
                            getEnabledSSLCiphers(this.sslHTTPProvider, true), sslHTTPProvider, httpClientAuthMode);
                } catch (final Exception e) {
                    logExplanation(e);
                    throw new ElasticsearchSecurityException(
                            "Error while initializing http SSL layer from PEM: " + e.toString(), e);
                }

            } else {
                throw new ElasticsearchException(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH + " or "
                        + SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_FILEPATH
                        + " must be set if http ssl is reqested.");
            }

        }
    }

    public SSLEngine createHTTPSSLEngine() throws SSLException {

        final SSLEngine engine = httpSslContext.newEngine(PooledByteBufAllocator.DEFAULT);
        engine.setEnabledProtocols(getEnabledSSLProtocols(this.sslHTTPProvider, true));
        return engine;

    }

    public SSLEngine createServerTransportSSLEngine() throws SSLException {

        final SSLEngine engine = transportServerSslContext.newEngine(PooledByteBufAllocator.DEFAULT);
        engine.setEnabledProtocols(getEnabledSSLProtocols(this.sslTransportServerProvider, false));
        return engine;

    }

    public SSLEngine createClientTransportSSLEngine(final String peerHost, final int peerPort) throws SSLException {

        if (peerHost != null) {
            final SSLEngine engine = transportClientSslContext.newEngine(PooledByteBufAllocator.DEFAULT, peerHost,
                    peerPort);

            final SSLParameters sslParams = new SSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            engine.setSSLParameters(sslParams);
            engine.setEnabledProtocols(getEnabledSSLProtocols(this.sslTransportClientProvider, false));
            return engine;
        } else {
            final SSLEngine engine = transportClientSslContext.newEngine(PooledByteBufAllocator.DEFAULT);
            engine.setEnabledProtocols(getEnabledSSLProtocols(this.sslTransportClientProvider, false));
            return engine;
        }

    }

    @Override
    public String getHTTPProviderName() {
        return sslHTTPProvider == null ? null : sslHTTPProvider.toString();
    }

    @Override
    public String getTransportServerProviderName() {
        return sslTransportServerProvider == null ? null : sslTransportServerProvider.toString();
    }

    @Override
    public String getTransportClientProviderName() {
        return sslTransportClientProvider == null ? null : sslTransportClientProvider.toString();
    }

    private void logOpenSSLInfos() {
        if (OpenDistroSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable()) {
            log.info("OpenSSL " + OpenSsl.versionString() + " (" + OpenSsl.version() + ") available");

            if (OpenSsl.version() < 0x10002000L) {
                log.warn(
                        "Outdated OpenSSL version detected. You should update to 1.0.2k or later. Currently installed: "
                                + OpenSsl.versionString());
            }

            if (!OpenSsl.supportsHostnameValidation()) {
                log.warn("Your OpenSSL version " + OpenSsl.versionString()
                        + " does not support hostname verification. You should update to 1.0.2k or later.");
            }

            log.debug("OpenSSL available ciphers " + OpenSsl.availableOpenSslCipherSuites());
        } else {
            log.info("OpenSSL not available (this is not an error, we simply fallback to built-in JDK SSL) because of "
                    + OpenSsl.unavailabilityCause());
        }
    }

    private List<String> getEnabledSSLCiphers(final SslProvider provider, boolean http) {
        if (provider == null) {
            return Collections.emptyList();
        }

        if (http) {
            return provider == SslProvider.JDK ? enabledHttpCiphersJDKProvider : enabledHttpCiphersOpenSSLProvider;
        } else {
            return provider == SslProvider.JDK ? enabledTransportCiphersJDKProvider
                    : enabledTransportCiphersOpenSSLProvider;
        }

    }
    
    private String[] getEnabledSSLProtocols(final SslProvider provider, boolean http) {
        if (provider == null) {
            return new String[0];
        }

        if (http) {
            return (provider == SslProvider.JDK ? enabledHttpProtocolsJDKProvider : enabledHttpProtocolsOpenSSLProvider).toArray(new String[0]);
        } else {
            return (provider == SslProvider.JDK ? enabledTransportProtocolsJDKProvider
                    : enabledTransportProtocolsOpenSSLProvider).toArray(new String[0]);
        }

    }

    private void initEnabledSSLCiphers() {

        final List<String> secureHttpSSLCiphers = SSLConfigConstants.getSecureSSLCiphers(settings, true);
        final List<String> secureTransportSSLCiphers = SSLConfigConstants.getSecureSSLCiphers(settings, false);
        final List<String> secureHttpSSLProtocols = Arrays.asList(SSLConfigConstants.getSecureSSLProtocols(settings, true));
        final List<String> secureTransportSSLProtocols = Arrays.asList(SSLConfigConstants.getSecureSSLProtocols(settings, false));

        if (OpenDistroSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable()) {
            final Set<String> openSSLSecureHttpCiphers = new HashSet<>();
            for (final String secure : secureHttpSSLCiphers) {
                if (OpenSsl.isCipherSuiteAvailable(secure)) {
                    openSSLSecureHttpCiphers.add(secure);
                }
            }
            
            
            log.debug("OPENSSL "+OpenSsl.versionString()+" supports the following ciphers (java-style) {}", OpenSsl.availableJavaCipherSuites());
            log.debug("OPENSSL "+OpenSsl.versionString()+" supports the following ciphers (openssl-style) {}", OpenSsl.availableOpenSslCipherSuites());

            enabledHttpCiphersOpenSSLProvider = Collections
                    .unmodifiableList(new ArrayList<String>(openSSLSecureHttpCiphers));
        } else {
            enabledHttpCiphersOpenSSLProvider = Collections.emptyList();
        }

        if (OpenDistroSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable()) {
            final Set<String> openSSLSecureTransportCiphers = new HashSet<>();
            for (final String secure : secureTransportSSLCiphers) {
                if (OpenSsl.isCipherSuiteAvailable(secure)) {
                    openSSLSecureTransportCiphers.add(secure);
                }
            }

            enabledTransportCiphersOpenSSLProvider = Collections
                    .unmodifiableList(new ArrayList<String>(openSSLSecureTransportCiphers));
        } else {
            enabledTransportCiphersOpenSSLProvider = Collections.emptyList();
        }
        
        if(OpenDistroSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable() && OpenSsl.version() > 0x10101009L) {
            enabledHttpProtocolsOpenSSLProvider = new ArrayList(Arrays.asList("TLSv1.3","TLSv1.2","TLSv1.1","TLSv1"));
            enabledHttpProtocolsOpenSSLProvider.retainAll(secureHttpSSLProtocols);
            enabledTransportProtocolsOpenSSLProvider = new ArrayList(Arrays.asList("TLSv1.3","TLSv1.2","TLSv1.1"));
            enabledTransportProtocolsOpenSSLProvider.retainAll(secureTransportSSLProtocols);
            
            log.info("OpenSSL supports TLSv1.3");
            
        } else if(OpenDistroSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable()){
            enabledHttpProtocolsOpenSSLProvider = new ArrayList(Arrays.asList("TLSv1.2","TLSv1.1","TLSv1"));
            enabledHttpProtocolsOpenSSLProvider.retainAll(secureHttpSSLProtocols);
            enabledTransportProtocolsOpenSSLProvider = new ArrayList(Arrays.asList("TLSv1.2","TLSv1.1"));
            enabledTransportProtocolsOpenSSLProvider.retainAll(secureTransportSSLProtocols);
        } else {
            enabledHttpProtocolsOpenSSLProvider = Collections.emptyList();
            enabledTransportProtocolsOpenSSLProvider = Collections.emptyList();
        }

        SSLEngine engine = null;
        List<String> jdkSupportedCiphers = null;
        List<String> jdkSupportedProtocols = null;
        try {
            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(null, null, null);
            engine = serverContext.createSSLEngine();
            jdkSupportedCiphers = Arrays.asList(engine.getEnabledCipherSuites());
            jdkSupportedProtocols = Arrays.asList(engine.getEnabledProtocols());
            log.debug("JVM supports the following {} protocols {}", jdkSupportedProtocols.size(),
                    jdkSupportedProtocols);
            log.debug("JVM supports the following {} ciphers {}", jdkSupportedCiphers.size(),
                    jdkSupportedCiphers);
            
            if(jdkSupportedProtocols.contains("TLSv1.3")) {
                log.info("JVM supports TLSv1.3");
            }
            
        } catch (final Throwable e) {
            log.error("Unable to determine supported ciphers due to " + e, e);
        } finally {
            if (engine != null) {
                try {
                    engine.closeInbound();
                } catch (SSLException e) {
                    log.debug("Unable to close inbound ssl engine", e);
                }
                engine.closeOutbound();
            }
        }

        if(jdkSupportedCiphers == null || jdkSupportedCiphers.isEmpty() || jdkSupportedProtocols == null || jdkSupportedProtocols.isEmpty()) {
            throw new ElasticsearchException("Unable to determine supported ciphers or protocols");
        }
        
        enabledHttpCiphersJDKProvider = new ArrayList<String>(jdkSupportedCiphers);
        enabledHttpCiphersJDKProvider.retainAll(secureHttpSSLCiphers);
        
        enabledTransportCiphersJDKProvider = new ArrayList<String>(jdkSupportedCiphers);
        enabledTransportCiphersJDKProvider.retainAll(secureTransportSSLCiphers);
        
        enabledHttpProtocolsJDKProvider = new ArrayList<String>(jdkSupportedProtocols);
        enabledHttpProtocolsJDKProvider.retainAll(secureHttpSSLProtocols);
        
        enabledTransportProtocolsJDKProvider = new ArrayList<String>(jdkSupportedProtocols);
        enabledTransportProtocolsJDKProvider.retainAll(secureTransportSSLProtocols);
    }

    private SslContext buildSSLServerContext(final PrivateKey _key, final X509Certificate[] _cert,
            final X509Certificate[] _trustedCerts, final Iterable<String> ciphers, final SslProvider sslProvider,
            final ClientAuth authMode) throws SSLException {

        final SslContextBuilder _sslContextBuilder = SslContextBuilder.forServer(_key, _cert).ciphers(ciphers)
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                .clientAuth(Objects.requireNonNull(authMode)) // https://github.com/netty/netty/issues/4722
                .sessionCacheSize(0).sessionTimeout(0).sslProvider(sslProvider);

        if (_trustedCerts != null && _trustedCerts.length > 0) {
            _sslContextBuilder.trustManager(_trustedCerts);
        }

        return buildSSLContext0(_sslContextBuilder);
    }

    private SslContext buildSSLServerContext(final File _key, final File _cert, final File _trustedCerts,
            final String pwd, final Iterable<String> ciphers, final SslProvider sslProvider, final ClientAuth authMode)
            throws SSLException {

        final SslContextBuilder _sslContextBuilder = SslContextBuilder.forServer(_cert, _key, pwd).ciphers(ciphers)
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                .clientAuth(Objects.requireNonNull(authMode)) // https://github.com/netty/netty/issues/4722
                .sessionCacheSize(0).sessionTimeout(0).sslProvider(sslProvider);

        if (_trustedCerts != null) {
            _sslContextBuilder.trustManager(_trustedCerts);
        }

        return buildSSLContext0(_sslContextBuilder);
    }

    private SslContext buildSSLClientContext(final PrivateKey _key, final X509Certificate[] _cert,
            final X509Certificate[] _trustedCerts, final Iterable<String> ciphers, final SslProvider sslProvider)
            throws SSLException {

        final SslContextBuilder _sslClientContextBuilder = SslContextBuilder.forClient().ciphers(ciphers)
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED).sessionCacheSize(0).sessionTimeout(0)
                .sslProvider(sslProvider).trustManager(_trustedCerts).keyManager(_key, _cert);

        return buildSSLContext0(_sslClientContextBuilder);

    }

    private SslContext buildSSLClientContext(final File _key, final File _cert, final File _trustedCerts,
            final String pwd, final Iterable<String> ciphers, final SslProvider sslProvider) throws SSLException {

        final SslContextBuilder _sslClientContextBuilder = SslContextBuilder.forClient().ciphers(ciphers)
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED).sessionCacheSize(0).sessionTimeout(0)
                .sslProvider(sslProvider).trustManager(_trustedCerts).keyManager(_cert, _key, pwd);

        return buildSSLContext0(_sslClientContextBuilder);

    }

    private SslContext buildSSLContext0(final SslContextBuilder sslContextBuilder) throws SSLException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        SslContext sslContext = null;
        try {
            sslContext = AccessController.doPrivileged(new PrivilegedExceptionAction<SslContext>() {
                @Override
                public SslContext run() throws Exception {
                    return sslContextBuilder.build();
                }
            });
        } catch (final PrivilegedActionException e) {
            throw (SSLException) e.getCause();
        }

        return sslContext;
    }

    private void logExplanation(Exception e) {
        if (ExceptionUtils.findMsg(e, "not contain valid private key") != null) {
            log.error("Your keystore or PEM does not contain a key. "
                    + "If you specified a key password, try removing it. "
                    + "If you did not specify a key password, perhaps you need to if the key is in fact password-protected. "
                    + "Maybe you just confused keys and certificates.");
        }

        if (ExceptionUtils.findMsg(e, "not contain valid certificates") != null) {
            log.error("Your keystore or PEM does not contain a certificate. Maybe you confused keys and certificates.");
        }
    }

    private static void checkPath(String keystoreFilePath, String fileNameLogOnly) {

        if (keystoreFilePath == null || keystoreFilePath.length() == 0) {
            throw new ElasticsearchException("Empty file path for " + fileNameLogOnly);
        }

        if (Files.isDirectory(Paths.get(keystoreFilePath), LinkOption.NOFOLLOW_LINKS)) {
            throw new ElasticsearchException(
                    "Is a directory: " + keystoreFilePath + " Expected a file for " + fileNameLogOnly);
        }

        if (!Files.isReadable(Paths.get(keystoreFilePath))) {
            throw new ElasticsearchException("Unable to read " + keystoreFilePath + " (" + Paths.get(keystoreFilePath)
                    + "). Please make sure this files exists and is readable regarding to permissions. Property: "
                    + fileNameLogOnly);
        }
    }
}
