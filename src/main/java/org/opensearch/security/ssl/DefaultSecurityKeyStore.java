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

package org.opensearch.security.ssl;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;

import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.security.ssl.util.CertFileProps;
import org.opensearch.security.ssl.util.CertFromFile;
import org.opensearch.security.ssl.util.CertFromKeystore;
import org.opensearch.security.ssl.util.CertFromTruststore;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.ssl.util.KeystoreProps;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.transport.NettyAllocator;

import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import io.netty.util.internal.PlatformDependent;

import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_HTTP_KEYSTORE_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_HTTP_PEMKEY_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD;

public class DefaultSecurityKeyStore implements SecurityKeyStore {

    private static final String DEFAULT_STORE_TYPE = "JKS";

    private void printJCEWarnings() {
        try {
            final int aesMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");

            if (aesMaxKeyLength < 256) {
                // CS-SUPPRESS-SINGLE: RegexpSingleline Java Cryptography Extension is unrelated to OpenSearch extensions
                log.info(
                    "AES-256 not supported, max key length for AES is {} bit."
                        + " (This is not an issue, it just limits possible encryption strength. To enable AES 256, install 'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files')",
                    aesMaxKeyLength
                );
                // CS-ENFORCE-SINGLE
            }
        } catch (final NoSuchAlgorithmException e) {
            log.error("AES encryption not supported (SG 1). ", e);
        }
    }

    private final Settings settings;
    private final Logger log = LogManager.getLogger(this.getClass());
    public final SslProvider sslHTTPProvider;
    public final SslProvider sslTransportServerProvider;
    public final SslProvider sslTransportClientProvider;
    private final boolean httpSSLEnabled;
    private final boolean transportSSLEnabled;

    private ArrayList<String> enabledHttpCiphersJDKProvider;
    private ArrayList<String> enabledHttpCiphersOpenSSLProvider;
    private ArrayList<String> enabledTransportCiphersJDKProvider;
    private ArrayList<String> enabledTransportCiphersOpenSSLProvider;

    private ArrayList<String> enabledHttpProtocolsJDKProvider;
    private ArrayList<String> enabledHttpProtocolsOpenSSLProvider;
    private ArrayList<String> enabledTransportProtocolsJDKProvider;
    private ArrayList<String> enabledTransportProtocolsOpenSSLProvider;

    private SslContext httpSslContext;
    private SslContext transportServerSslContext;
    private SslContext transportClientSslContext;
    private X509Certificate[] transportCerts;
    private X509Certificate[] httpCerts;
    private final Environment env;

    public DefaultSecurityKeyStore(final Settings settings, final Path configPath) {
        super();
        this.settings = settings;
        Environment _env;
        try {
            _env = new Environment(settings, configPath);
        } catch (IllegalStateException e) {
            _env = null;
        }
        env = _env;
        httpSSLEnabled = settings.getAsBoolean(
            SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED,
            SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_DEFAULT
        );
        transportSSLEnabled = settings.getAsBoolean(
            SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED,
            SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT
        );
        final boolean useOpenSSLForHttpIfAvailable = OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED
            && settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, true);
        final boolean useOpenSSLForTransportIfAvailable = OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED
            && settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, true);

        if (!OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED
            && OpenSsl.isAvailable()
            && (settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, true)
                || settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, true))) {
            if (PlatformDependent.javaVersion() < 12) {
                log.warn(
                    "Support for OpenSSL with Java 11 or prior versions require using Netty allocator. Set 'opensearch.unsafe.use_netty_default_allocator' system property to true"
                );
            } else {
                log.warn(
                    "Support for OpenSSL with Java 12+ has been removed from Open Distro Security since Elasticsearch 7.4.0. Using JDK SSL instead."
                );
            }
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

        log.debug(
            "sslTransportClientProvider:{} with ciphers {}",
            sslTransportClientProvider,
            getEnabledSSLCiphers(sslTransportClientProvider, false)
        );
        log.debug(
            "sslTransportServerProvider:{} with ciphers {}",
            sslTransportServerProvider,
            getEnabledSSLCiphers(sslTransportServerProvider, false)
        );
        log.debug("sslHTTPProvider:{} with ciphers {}", sslHTTPProvider, getEnabledSSLCiphers(sslHTTPProvider, true));

        log.info(
            "Enabled TLS protocols for transport layer : {}",
            Arrays.toString(getEnabledSSLProtocols(sslTransportServerProvider, false))
        );
        log.info("Enabled TLS protocols for HTTP layer      : {}", Arrays.toString(getEnabledSSLProtocols(sslHTTPProvider, true)));

        log.debug(
            "sslTransportClientProvider:{} with protocols {}",
            sslTransportClientProvider,
            getEnabledSSLProtocols(sslTransportClientProvider, false)
        );
        log.debug(
            "sslTransportServerProvider:{} with protocols {}",
            sslTransportServerProvider,
            getEnabledSSLProtocols(sslTransportServerProvider, false)
        );
        log.debug("sslHTTPProvider:{} with protocols {}", sslHTTPProvider, getEnabledSSLProtocols(sslHTTPProvider, true));

        if (transportSSLEnabled
            && (getEnabledSSLCiphers(sslTransportClientProvider, false).isEmpty()
                || getEnabledSSLCiphers(sslTransportServerProvider, false).isEmpty())) {
            throw new OpenSearchSecurityException("no valid cipher suites for transport protocol");
        }

        if (httpSSLEnabled && getEnabledSSLCiphers(sslHTTPProvider, true).isEmpty()) {
            throw new OpenSearchSecurityException("no valid cipher suites for https");
        }

        if (transportSSLEnabled && getEnabledSSLCiphers(sslTransportServerProvider, false).isEmpty()) {
            throw new OpenSearchSecurityException("no ssl protocols for transport protocol");
        }

        if (transportSSLEnabled && getEnabledSSLCiphers(sslTransportClientProvider, false).isEmpty()) {
            throw new OpenSearchSecurityException("no ssl protocols for transport protocol");
        }

        if (httpSSLEnabled && getEnabledSSLCiphers(sslHTTPProvider, true).isEmpty()) {
            throw new OpenSearchSecurityException("no ssl protocols for https");
        }
    }

    private String resolve(String propName, boolean mustBeValid) {

        final String originalPath = settings.get(propName, null);
        String path = originalPath;
        log.debug("Value for {} is {}", propName, originalPath);

        if (env != null && originalPath != null && originalPath.length() > 0) {
            path = env.configDir().resolve(originalPath).toAbsolutePath().toString();
            log.debug("Resolved {} to {} against {}", originalPath, path, env.configDir().toAbsolutePath().toString());
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
            log.info(
                "Config directory is {}/, from there the key- and truststore files are resolved relatively",
                env.configDir().toAbsolutePath()
            );
        }

        if (transportSSLEnabled) {
            initTransportSSLConfig();
        }

        final boolean client = !"node".equals(this.settings.get(OpenSearchSecuritySSLPlugin.CLIENT_TYPE));

        if (!client && httpSSLEnabled) {
            initHttpSSLConfig();
        }
    }

    /**
     * Initializes certs used for node to node communication
     */
    public void initTransportSSLConfig() {
        // when extendedKeyUsageEnabled and we use keyStore, client/server certs will be in the
        // same keyStore file
        // when extendedKeyUsageEnabled and we use rawFiles, client/server certs will be in
        // different files
        // That's why useRawFiles checks for extra location
        final boolean useKeyStore = settings.hasValue(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH);
        final boolean useRawFiles = settings.hasValue(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH)
            || (settings.hasValue(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH)
                && settings.hasValue(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH));

        final boolean extendedKeyUsageEnabled = settings.getAsBoolean(
            SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED,
            SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED_DEFAULT
        );

        if (useKeyStore) {

            final String keystoreFilePath = resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, true);
            final String keystoreType = settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, DEFAULT_STORE_TYPE);
            final String keystorePassword = SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD.getSetting(
                settings,
                SSLConfigConstants.DEFAULT_STORE_PASSWORD
            );

            final String truststoreFilePath = resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, true);

            if (settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, null) == null) {
                throw new OpenSearchException(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH + " must be set if transport ssl is requested."
                );
            }

            final String truststoreType = settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, DEFAULT_STORE_TYPE);
            final String truststorePassword = SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD.getSetting(settings);

            KeystoreProps keystoreProps = new KeystoreProps(keystoreFilePath, keystoreType, keystorePassword);

            KeystoreProps truststoreProps = new KeystoreProps(truststoreFilePath, truststoreType, truststorePassword);
            try {
                CertFromKeystore certFromKeystore;
                CertFromTruststore certFromTruststore;
                if (extendedKeyUsageEnabled) {
                    final String truststoreServerAlias = settings.get(
                        SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS,
                        null
                    );
                    final String truststoreClientAlias = settings.get(
                        SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS,
                        null
                    );
                    final String keystoreServerAlias = settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS, null);
                    final String keystoreClientAlias = settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS, null);
                    final String serverKeyPassword = SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD.getSetting(
                        settings,
                        keystorePassword
                    );
                    final String clientKeyPassword = SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD.getSetting(
                        settings,
                        keystorePassword
                    );

                    // we require all aliases to be set explicitly
                    // because they should be different for client and server
                    if (keystoreServerAlias == null
                        || keystoreClientAlias == null
                        || truststoreServerAlias == null
                        || truststoreClientAlias == null) {
                        throw new OpenSearchException(
                            SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS
                                + ", "
                                + SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS
                                + ", "
                                + SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS
                                + ", "
                                + SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS
                                + " must be set when "
                                + SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED
                                + " is true."
                        );
                    }

                    certFromKeystore = new CertFromKeystore(
                        keystoreProps,
                        keystoreServerAlias,
                        keystoreClientAlias,
                        serverKeyPassword,
                        clientKeyPassword
                    );
                    certFromTruststore = new CertFromTruststore(truststoreProps, truststoreServerAlias, truststoreClientAlias);
                } else {
                    // when alias is null, we take first entry in the store
                    final String truststoreAlias = settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS, null);
                    final String keystoreAlias = settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, null);
                    final String keyPassword = SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD.getSetting(settings, keystorePassword);

                    certFromKeystore = new CertFromKeystore(keystoreProps, keystoreAlias, keyPassword);
                    certFromTruststore = new CertFromTruststore(truststoreProps, truststoreAlias);
                }

                validateNewCerts(transportCerts, certFromKeystore.getCerts());
                transportServerSslContext = buildSSLServerContext(
                    certFromKeystore.getServerKey(),
                    certFromKeystore.getServerCert(),
                    certFromTruststore.getServerTrustedCerts(),
                    getEnabledSSLCiphers(this.sslTransportServerProvider, false),
                    this.sslTransportServerProvider,
                    ClientAuth.REQUIRE
                );
                transportClientSslContext = buildSSLClientContext(
                    certFromKeystore.getClientKey(),
                    certFromKeystore.getClientCert(),
                    certFromTruststore.getClientTrustedCerts(),
                    getEnabledSSLCiphers(sslTransportClientProvider, false),
                    sslTransportClientProvider
                );
                setTransportSSLCerts(certFromKeystore.getCerts());
            } catch (final Exception e) {
                logExplanation(e);
                throw new OpenSearchSecurityException("Error while initializing transport SSL layer: " + e.toString(), e);
            }

        } else if (useRawFiles) {
            try {
                CertFromFile certFromFile;
                if (extendedKeyUsageEnabled) {
                    CertFileProps clientCertProps = new CertFileProps(
                        resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH, true),
                        resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH, true),
                        resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH, true),
                        SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD.getSetting(settings)
                    );

                    CertFileProps serverCertProps = new CertFileProps(
                        resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH, true),
                        resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH, true),
                        resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH, true),
                        SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD.getSetting(settings)
                    );

                    certFromFile = new CertFromFile(clientCertProps, serverCertProps);
                } else {
                    CertFileProps certProps = new CertFileProps(
                        resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, true),
                        resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, true),
                        resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, true),
                        SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD.getSetting(settings)
                    );
                    certFromFile = new CertFromFile(certProps);
                }

                validateNewCerts(transportCerts, certFromFile.getCerts());
                transportServerSslContext = buildSSLServerContext(
                    certFromFile.getServerPemKey(),
                    certFromFile.getServerPemCert(),
                    certFromFile.getServerTrustedCas(),
                    certFromFile.getServerPemKeyPassword(),
                    getEnabledSSLCiphers(this.sslTransportServerProvider, false),
                    this.sslTransportServerProvider,
                    ClientAuth.REQUIRE
                );
                transportClientSslContext = buildSSLClientContext(
                    certFromFile.getClientPemKey(),
                    certFromFile.getClientPemCert(),
                    certFromFile.getClientTrustedCas(),
                    certFromFile.getClientPemKeyPassword(),
                    getEnabledSSLCiphers(sslTransportClientProvider, false),
                    sslTransportClientProvider
                );
                setTransportSSLCerts(certFromFile.getCerts());

            } catch (final Exception e) {
                logExplanation(e);
                throw new OpenSearchSecurityException("Error while initializing transport SSL layer from PEM: " + e.toString(), e);
            }
        } else {
            throw new OpenSearchException(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH
                    + " or "
                    + SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH
                    + " and "
                    + SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH
                    + " must be set if transport ssl is requested."
            );
        }
    }

    /**
     * Initializes certs used for client https communication
     */
    public void initHttpSSLConfig() {
        final boolean useKeyStore = settings.hasValue(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH);
        final boolean useRawFiles = settings.hasValue(SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH);
        final ClientAuth httpClientAuthMode = ClientAuth.valueOf(
            settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, ClientAuth.OPTIONAL.toString())
        );

        if (useKeyStore) {

            final String keystoreFilePath = resolve(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, true);
            final String keystoreType = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_TYPE, DEFAULT_STORE_TYPE);
            final String keystorePassword = SECURITY_SSL_HTTP_KEYSTORE_PASSWORD.getSetting(
                settings,
                SSLConfigConstants.DEFAULT_STORE_PASSWORD
            );

            final String keyPassword = SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD.getSetting(settings, keystorePassword);

            final String keystoreAlias = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, null);

            log.info("HTTPS client auth mode {}", httpClientAuthMode);

            if (settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, null) == null) {
                throw new OpenSearchException(
                    SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH + " must be set if https is requested."
                );
            }

            if (httpClientAuthMode == ClientAuth.REQUIRE) {

                if (settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, null) == null) {
                    throw new OpenSearchException(
                        SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH + " must be set if http ssl and client auth is requested."
                    );
                }

            }

            try {

                KeystoreProps keystoreProps = new KeystoreProps(keystoreFilePath, keystoreType, keystorePassword);

                CertFromKeystore certFromKeystore = new CertFromKeystore(keystoreProps, keystoreAlias, keyPassword);

                CertFromTruststore certFromTruststore = CertFromTruststore.Empty();
                if (settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, null) != null) {

                    final String truststoreFilePath = resolve(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, true);

                    final String truststoreType = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, DEFAULT_STORE_TYPE);
                    final String truststorePassword = SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD.getSetting(settings);

                    final String truststoreAlias = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS, null);

                    KeystoreProps truststoreProps = new KeystoreProps(truststoreFilePath, truststoreType, truststorePassword);

                    certFromTruststore = new CertFromTruststore(truststoreProps, truststoreAlias);
                }

                validateNewCerts(httpCerts, certFromKeystore.getCerts());
                httpSslContext = buildSSLServerContext(
                    certFromKeystore.getServerKey(),
                    certFromKeystore.getServerCert(),
                    certFromTruststore.getServerTrustedCerts(),
                    getEnabledSSLCiphers(this.sslHTTPProvider, true),
                    sslHTTPProvider,
                    httpClientAuthMode
                );
                setHttpSSLCerts(certFromKeystore.getCerts());

            } catch (final Exception e) {
                logExplanation(e);
                throw new OpenSearchSecurityException("Error while initializing HTTP SSL layer: " + e.toString(), e);
            }

        } else if (useRawFiles) {
            final String trustedCas = resolve(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, false);
            if (httpClientAuthMode == ClientAuth.REQUIRE) {
                checkPath(trustedCas, SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH);
            }

            try {
                CertFileProps certFileProps = new CertFileProps(
                    resolve(SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH, true),
                    resolve(SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, true),
                    trustedCas,
                    SECURITY_SSL_HTTP_PEMKEY_PASSWORD.getSetting(settings)
                );
                CertFromFile certFromFile = new CertFromFile(certFileProps);

                validateNewCerts(httpCerts, certFromFile.getCerts());
                httpSslContext = buildSSLServerContext(
                    certFromFile.getServerPemKey(),
                    certFromFile.getServerPemCert(),
                    certFromFile.getServerTrustedCas(),
                    SECURITY_SSL_HTTP_PEMKEY_PASSWORD.getSetting(settings),
                    getEnabledSSLCiphers(this.sslHTTPProvider, true),
                    sslHTTPProvider,
                    httpClientAuthMode
                );
                setHttpSSLCerts(certFromFile.getCerts());

            } catch (final Exception e) {
                logExplanation(e);
                throw new OpenSearchSecurityException("Error while initializing http SSL layer from PEM: " + e.toString(), e);
            }

        } else {
            throw new OpenSearchException(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH
                    + " or "
                    + SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH
                    + " must be set if http ssl is requested."
            );
        }
    }

    /**
     * If the current and new certificates are same, skip remaining checks.
     * For new X509 cert to be valid Issuer, Subject DN must be the same and
     * new certificates should expire after current ones.
     * @param currentX509Certs  Array of current x509 certificates
     * @param newX509Certs      Array of x509 certificates which will replace our current cert
     * @throws Exception if certificate is invalid
     */
    private void validateNewCerts(final X509Certificate[] currentX509Certs, final X509Certificate[] newX509Certs) throws Exception {

        // First time we init certs ignore validity check
        if (currentX509Certs == null) {
            return;
        }

        if (areSameCerts(currentX509Certs, newX509Certs)) {
            return;
        }

        // Check if new X509 certs have valid expiry date
        if (!hasValidExpiryDates(currentX509Certs, newX509Certs)) {
            throw new Exception("New certificates should not expire before the current ones.");
        }

        // Check if new X509 certs have valid IssuerDN, SubjectDN or SAN
        if (!hasValidDNs(currentX509Certs, newX509Certs)) {
            throw new Exception("New Certs do not have valid Issuer DN, Subject DN or SAN.");
        }
    }

    /**
     * Check if new X509 certs have same IssuerDN/SubjectDN as current certificates.
     * @param currentX509Certs Array of current X509Certificates.
     * @param newX509Certs Array of new X509Certificates.
     * @return true if all Issuer DN and Subject DN pairs match; false otherwise.
     * @throws Exception if certificate is invalid.
     */
    private boolean hasValidDNs(final X509Certificate[] currentX509Certs, final X509Certificate[] newX509Certs) {

        final Function<? super X509Certificate, String> formatDNString = cert -> {
            final String issuerDn = cert != null && cert.getIssuerX500Principal() != null ? cert.getIssuerX500Principal().getName() : "";
            final String subjectDn = cert != null && cert.getSubjectX500Principal() != null ? cert.getSubjectX500Principal().getName() : "";
            final String san = getSubjectAlternativeNames(cert);
            return String.format("%s/%s/%s", issuerDn, subjectDn, san);
        };

        final List<String> currentCertDNList = Arrays.stream(currentX509Certs).map(formatDNString).sorted().collect(Collectors.toList());

        final List<String> newCertDNList = Arrays.stream(newX509Certs).map(formatDNString).sorted().collect(Collectors.toList());

        return currentCertDNList.equals(newCertDNList);
    }

    /**
     * Check if new X509 certs have expiry date after the current X509 certs.
     * @param currentX509Certs Array of current X509Certificates.
     * @param newX509Certs Array of new X509Certificates.
     * @return true if all of the new certificates expire after the currentX509 certificates.
     * @throws Exception if certificate is invalid.
     */
    private boolean hasValidExpiryDates(final X509Certificate[] currentX509Certs, final X509Certificate[] newX509Certs) {

        // Get earliest expiry date for current certificates
        final Date earliestExpiryDate = Arrays.stream(currentX509Certs).map(c -> c.getNotAfter()).min(Date::compareTo).get();

        // New certificates that expire before or on the same date as the current ones are invalid.
        boolean newCertsExpireBeforeCurrentCerts = Arrays.stream(newX509Certs).anyMatch(cert -> {
            Date notAfterDate = cert.getNotAfter();
            return notAfterDate.before(earliestExpiryDate) || notAfterDate.equals(earliestExpiryDate);
        });

        return !newCertsExpireBeforeCurrentCerts;
    }

    /**
     * Check if new X509 certs have same signature has as the current X509 certs.
     * @param currentX509Certs Array of current X509Certificates.
     * @param newX509Certs Array of new X509Certificates.
     * @return true if all of the new certificates have the same signature as currentX509 certificates.
     * @return false if any new certificate signature is different than currentX509 certificates
     */

    private boolean areSameCerts(final X509Certificate[] currentX509Certs, final X509Certificate[] newX509Certs) {

        final Function<? super X509Certificate, String> certificateSignature = cert -> {
            final byte[] signature = cert != null && cert.getSignature() != null ? cert.getSignature() : null;
            return new String(signature, StandardCharsets.UTF_8);
        };

        final Set<String> currentCertSignatureSet = Arrays.stream(currentX509Certs).map(certificateSignature).collect(Collectors.toSet());

        final Set<String> newCertSignatureSet = Arrays.stream(newX509Certs).map(certificateSignature).collect(Collectors.toSet());

        return currentCertSignatureSet.equals(newCertSignatureSet);
    }

    public SSLEngine createHTTPSSLEngine() throws SSLException {
        final SSLEngine engine = httpSslContext.newEngine(NettyAllocator.getAllocator());
        engine.setEnabledProtocols(getEnabledSSLProtocols(this.sslHTTPProvider, true));
        return engine;

    }

    public SSLEngine createServerTransportSSLEngine() throws SSLException {
        final SSLEngine engine = transportServerSslContext.newEngine(NettyAllocator.getAllocator());
        engine.setEnabledProtocols(getEnabledSSLProtocols(this.sslTransportServerProvider, false));
        return engine;
    }

    public SSLEngine createClientTransportSSLEngine(final String peerHost, final int peerPort) throws SSLException {
        if (peerHost != null) {
            final SSLEngine engine = transportClientSslContext.newEngine(NettyAllocator.getAllocator(), peerHost, peerPort);

            final SSLParameters sslParams = new SSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            engine.setSSLParameters(sslParams);
            engine.setEnabledProtocols(getEnabledSSLProtocols(this.sslTransportClientProvider, false));
            return engine;
        } else {
            final SSLEngine engine = transportClientSslContext.newEngine(NettyAllocator.getAllocator());
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

    @Override
    public X509Certificate[] getTransportCerts() {
        return transportCerts;
    }

    @Override
    public X509Certificate[] getHttpCerts() {
        return httpCerts;
    }

    /**
     * Sets the transport X509Certificates.
     * @param certs          New X509 Certificates
     */
    private void setTransportSSLCerts(X509Certificate[] certs) {
        this.transportCerts = certs;
    }

    /**
     * Sets the http X509Certificates.
     * @param certs          New X509 Certificates
     */
    private void setHttpSSLCerts(X509Certificate[] certs) {
        this.httpCerts = certs;
    }

    private void logOpenSSLInfos() {
        if (OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable()) {
            log.info("OpenSSL {} ({}) available", OpenSsl.versionString(), OpenSsl.version());

            if (OpenSsl.version() < 0x10002000L) {
                log.warn(
                    "Outdated OpenSSL version detected. You should update to 1.0.2k or later. Currently installed: {}",
                    OpenSsl.versionString()
                );
            }

            if (!OpenSsl.supportsHostnameValidation()) {
                log.warn(
                    "Your OpenSSL version {} does not support hostname verification. You should update to 1.0.2k or later.",
                    OpenSsl.versionString()
                );
            }

            log.debug("OpenSSL available ciphers {}", OpenSsl.availableOpenSslCipherSuites());
        } else {
            log.info(
                "OpenSSL not available (this is not an error, we simply fallback to built-in JDK SSL) because of "
                    + OpenSsl.unavailabilityCause()
            );
        }
    }

    private List<String> getEnabledSSLCiphers(final SslProvider provider, boolean http) {
        if (provider == null) {
            return Collections.emptyList();
        }

        if (http) {
            return ImmutableList.copyOf(provider == SslProvider.JDK ? enabledHttpCiphersJDKProvider : enabledHttpCiphersOpenSSLProvider);
        } else {
            return ImmutableList.copyOf(
                provider == SslProvider.JDK ? enabledTransportCiphersJDKProvider : enabledTransportCiphersOpenSSLProvider
            );
        }

    }

    private String[] getEnabledSSLProtocols(final SslProvider provider, boolean http) {
        if (provider == null) {
            return new String[0];
        }

        if (http) {
            return (provider == SslProvider.JDK ? enabledHttpProtocolsJDKProvider : enabledHttpProtocolsOpenSSLProvider).toArray(
                new String[0]
            );
        } else {
            return (provider == SslProvider.JDK ? enabledTransportProtocolsJDKProvider : enabledTransportProtocolsOpenSSLProvider).toArray(
                new String[0]
            );
        }

    }

    @SuppressWarnings("removal")
    private void initEnabledSSLCiphers() {

        final ImmutableSet<String> allowedSecureHttpSSLCiphers = ImmutableSet.copyOf(
            SSLConfigConstants.getSecureSSLCiphers(settings, true)
        );
        final ImmutableSet<String> allowedSecureTransportSSLCiphers = ImmutableSet.copyOf(
            SSLConfigConstants.getSecureSSLCiphers(settings, false)
        );
        final ImmutableSet<String> allowedSecureHttpSSLProtocols = ImmutableSet.copyOf(
            (SSLConfigConstants.getSecureSSLProtocols(settings, true))
        );
        final ImmutableSet<String> allowedSecureTransportSSLProtocols = ImmutableSet.copyOf(
            SSLConfigConstants.getSecureSSLProtocols(settings, false)
        );

        if (OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable()) {
            final Set<String> openSSLSecureHttpCiphers = new HashSet<>();
            for (final String secure : allowedSecureHttpSSLCiphers) {
                if (OpenSsl.isCipherSuiteAvailable(secure)) {
                    openSSLSecureHttpCiphers.add(secure);
                }
            }

            log.debug(
                "OPENSSL {} supports the following ciphers (java-style) {}",
                OpenSsl.versionString(),
                OpenSsl.availableJavaCipherSuites()
            );
            log.debug(
                "OPENSSL {} supports the following ciphers (openssl-style) {}",
                OpenSsl.versionString(),
                OpenSsl.availableOpenSslCipherSuites()
            );

            enabledHttpCiphersOpenSSLProvider = new ArrayList<String>(openSSLSecureHttpCiphers);
        } else {
            enabledHttpCiphersOpenSSLProvider = new ArrayList<String>();
        }

        if (OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable()) {
            final Set<String> openSSLSecureTransportCiphers = new HashSet<>();
            for (final String secure : allowedSecureTransportSSLCiphers) {
                if (OpenSsl.isCipherSuiteAvailable(secure)) {
                    openSSLSecureTransportCiphers.add(secure);
                }
            }

            enabledTransportCiphersOpenSSLProvider = new ArrayList<String>(openSSLSecureTransportCiphers);
        } else {
            enabledTransportCiphersOpenSSLProvider = new ArrayList<String>();
        }

        if (OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable() && OpenSsl.version() > 0x10101009L) {
            enabledHttpProtocolsOpenSSLProvider = new ArrayList<>(Arrays.asList("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"));
            enabledHttpProtocolsOpenSSLProvider.retainAll(allowedSecureHttpSSLProtocols);
            enabledTransportProtocolsOpenSSLProvider = new ArrayList<>(Arrays.asList("TLSv1.3", "TLSv1.2", "TLSv1.1"));
            enabledTransportProtocolsOpenSSLProvider.retainAll(allowedSecureTransportSSLProtocols);

            log.info("OpenSSL supports TLSv1.3");

        } else if (OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable()) {
            enabledHttpProtocolsOpenSSLProvider = new ArrayList<>(Arrays.asList("TLSv1.2", "TLSv1.1", "TLSv1"));
            enabledHttpProtocolsOpenSSLProvider.retainAll(allowedSecureHttpSSLProtocols);
            enabledTransportProtocolsOpenSSLProvider = new ArrayList<>(Arrays.asList("TLSv1.2", "TLSv1.1"));
            enabledTransportProtocolsOpenSSLProvider.retainAll(allowedSecureTransportSSLProtocols);
        } else {
            enabledHttpProtocolsOpenSSLProvider = new ArrayList<>();
            enabledTransportProtocolsOpenSSLProvider = new ArrayList<>();
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
            log.debug("JVM supports the following {} protocols {}", jdkSupportedProtocols.size(), jdkSupportedProtocols);
            log.debug("JVM supports the following {} ciphers {}", jdkSupportedCiphers.size(), jdkSupportedCiphers);

            if (jdkSupportedProtocols.contains("TLSv1.3")) {
                log.info("JVM supports TLSv1.3");
            }

        } catch (final Throwable e) {
            log.error("Unable to determine supported ciphers due to ", e);
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

        if (jdkSupportedCiphers == null
            || jdkSupportedCiphers.isEmpty()
            || jdkSupportedProtocols == null
            || jdkSupportedProtocols.isEmpty()) {
            throw new OpenSearchException("Unable to determine supported ciphers or protocols");
        }

        enabledHttpCiphersJDKProvider = new ArrayList<String>(jdkSupportedCiphers);
        enabledHttpCiphersJDKProvider.retainAll(allowedSecureHttpSSLCiphers);

        enabledTransportCiphersJDKProvider = new ArrayList<String>(jdkSupportedCiphers);
        enabledTransportCiphersJDKProvider.retainAll(allowedSecureTransportSSLCiphers);

        enabledHttpProtocolsJDKProvider = new ArrayList<String>(jdkSupportedProtocols);
        enabledHttpProtocolsJDKProvider.retainAll(allowedSecureHttpSSLProtocols);

        enabledTransportProtocolsJDKProvider = new ArrayList<String>(jdkSupportedProtocols);
        enabledTransportProtocolsJDKProvider.retainAll(allowedSecureTransportSSLProtocols);
    }

    private SslContext buildSSLServerContext(
        final PrivateKey _key,
        final X509Certificate[] _cert,
        final X509Certificate[] _trustedCerts,
        final Iterable<String> ciphers,
        final SslProvider sslProvider,
        final ClientAuth authMode
    ) throws SSLException {

        try {
            final SslContextBuilder _sslContextBuilder = AccessController.doPrivileged(new PrivilegedExceptionAction<SslContextBuilder>() {
                @Override
                public SslContextBuilder run() throws Exception {
                    return configureSSLServerContextBuilder(SslContextBuilder.forServer(_key, _cert), sslProvider, ciphers, authMode);
                }
            });

            if (_trustedCerts != null && _trustedCerts.length > 0) {
                _sslContextBuilder.trustManager(_trustedCerts);
            }

            return buildSSLContext0(_sslContextBuilder);
        } catch (final PrivilegedActionException e) {
            if (e.getCause() instanceof SSLException) {
                throw (SSLException) e.getCause();
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private SslContext buildSSLServerContext(
        final File _key,
        final File _cert,
        final File _trustedCerts,
        final String pwd,
        final Iterable<String> ciphers,
        final SslProvider sslProvider,
        final ClientAuth authMode
    ) throws SSLException {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            final SslContextBuilder _sslContextBuilder = AccessController.doPrivileged(new PrivilegedExceptionAction<SslContextBuilder>() {
                @Override
                public SslContextBuilder run() throws Exception {
                    return configureSSLServerContextBuilder(SslContextBuilder.forServer(_cert, _key, pwd), sslProvider, ciphers, authMode);
                }
            });

            if (_trustedCerts != null) {
                _sslContextBuilder.trustManager(_trustedCerts);
            }

            return buildSSLContext0(_sslContextBuilder);
        } catch (final PrivilegedActionException e) {
            if (e.getCause() instanceof SSLException) {
                throw (SSLException) e.getCause();
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private SslContextBuilder configureSSLServerContextBuilder(
        final SslContextBuilder builder,
        final SslProvider sslProvider,
        final Iterable<String> ciphers,
        final ClientAuth authMode
    ) {
        return builder.ciphers(
            Stream.concat(Http2SecurityUtil.CIPHERS.stream(), StreamSupport.stream(ciphers.spliterator(), false))
                .collect(Collectors.toSet()),
            SupportedCipherSuiteFilter.INSTANCE
        )
            .clientAuth(Objects.requireNonNull(authMode))
            .sessionCacheSize(0)
            .sessionTimeout(0)
            .sslProvider(sslProvider)
            .applicationProtocolConfig(
                new ApplicationProtocolConfig(
                    Protocol.ALPN,
                    // NO_ADVERTISE is currently the only mode supported by both OpenSsl and JDK providers.
                    SelectorFailureBehavior.NO_ADVERTISE,
                    // ACCEPT is currently the only mode supported by both OpenSsl and JDK providers.
                    SelectedListenerFailureBehavior.ACCEPT,
                    ApplicationProtocolNames.HTTP_2,
                    ApplicationProtocolNames.HTTP_1_1
                )
            );
    }

    private SslContext buildSSLClientContext(
        final PrivateKey _key,
        final X509Certificate[] _cert,
        final X509Certificate[] _trustedCerts,
        final Iterable<String> ciphers,
        final SslProvider sslProvider
    ) throws SSLException {

        final SslContextBuilder _sslClientContextBuilder = SslContextBuilder.forClient()
            .ciphers(ciphers)
            .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
            .sessionCacheSize(0)
            .sessionTimeout(0)
            .sslProvider(sslProvider)
            .trustManager(_trustedCerts)
            .keyManager(_key, _cert);

        return buildSSLContext0(_sslClientContextBuilder);

    }

    private SslContext buildSSLClientContext(
        final File _key,
        final File _cert,
        final File _trustedCerts,
        final String pwd,
        final Iterable<String> ciphers,
        final SslProvider sslProvider
    ) throws SSLException {

        final SslContextBuilder _sslClientContextBuilder = SslContextBuilder.forClient()
            .ciphers(ciphers)
            .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
            .sessionCacheSize(0)
            .sessionTimeout(0)
            .sslProvider(sslProvider)
            .trustManager(_trustedCerts)
            .keyManager(_cert, _key, pwd);

        return buildSSLContext0(_sslClientContextBuilder);

    }

    @SuppressWarnings("removal")
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
            if (e.getCause() instanceof SSLException) {
                throw (SSLException) e.getCause();
            } else {
                throw new RuntimeException(e);
            }
        }

        return sslContext;
    }

    private void logExplanation(Exception e) {
        if (ExceptionUtils.findMsg(e, "not contain valid private key") != null) {
            log.error(
                "Your keystore or PEM does not contain a key. "
                    + "If you specified a key password, try removing it. "
                    + "If you did not specify a key password, perhaps you need to if the key is in fact password-protected. "
                    + "Maybe you just confused keys and certificates."
            );
        }

        if (ExceptionUtils.findMsg(e, "not contain valid certificates") != null) {
            log.error("Your keystore or PEM does not contain a certificate. Maybe you confused keys and certificates.");
        }
    }

    private static void checkPath(String keystoreFilePath, String fileNameLogOnly) {

        if (keystoreFilePath == null || keystoreFilePath.length() == 0) {
            throw new OpenSearchException("Empty file path for " + fileNameLogOnly);
        }

        if (Files.isDirectory(Paths.get(keystoreFilePath), LinkOption.NOFOLLOW_LINKS)) {
            throw new OpenSearchException("Is a directory: " + keystoreFilePath + " Expected a file for " + fileNameLogOnly);
        }

        if (!Files.isReadable(Paths.get(keystoreFilePath))) {
            throw new OpenSearchException(
                "Unable to read "
                    + keystoreFilePath
                    + " ("
                    + Paths.get(keystoreFilePath)
                    + "). Please make sure this files exists and is readable regarding to permissions. Property: "
                    + fileNameLogOnly
            );
        }
    }

    @Override
    public String getSubjectAlternativeNames(X509Certificate cert) {
        String san = "";
        try {
            Collection<List<?>> altNames = cert != null && cert.getSubjectAlternativeNames() != null
                ? cert.getSubjectAlternativeNames()
                : null;
            if (altNames != null) {
                Collection<List<?>> sans = new ArrayList<>();
                for (List<?> altName : altNames) {
                    Integer type = (Integer) altName.get(0);
                    // otherName requires parsing to string
                    if (type == 0) {
                        List<?> otherName = getOtherName(altName);
                        if (otherName != null) {
                            sans.add(Arrays.asList(type, otherName));
                        }
                    } else {
                        sans.add(altName);
                    }
                }
                san = sans.toString();
            }
        } catch (CertificateParsingException e) {
            log.error("Issue parsing SubjectAlternativeName:", e);
        }

        return san;
    }

    private List<String> getOtherName(List<?> altName) {
        if (altName.size() < 2) {
            log.warn("Couldn't parse subject alternative names");
            return null;
        }
        try (final ASN1InputStream in = new ASN1InputStream((byte[]) altName.get(1))) {
            final ASN1Primitive asn1Primitive = in.readObject();
            final ASN1Sequence sequence = ASN1Sequence.getInstance(asn1Primitive);
            final ASN1ObjectIdentifier asn1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
            final ASN1TaggedObject asn1TaggedObject = ASN1TaggedObject.getInstance(sequence.getObjectAt(1));
            ASN1Object maybeTaggedAsn1Primitive = asn1TaggedObject.getBaseObject();
            if (maybeTaggedAsn1Primitive instanceof ASN1TaggedObject) {
                maybeTaggedAsn1Primitive = ASN1TaggedObject.getInstance(maybeTaggedAsn1Primitive).getBaseObject();
            }
            if (maybeTaggedAsn1Primitive instanceof ASN1String) {
                return ImmutableList.of(asn1ObjectIdentifier.getId(), maybeTaggedAsn1Primitive.toString());
            } else {
                log.warn("Couldn't parse subject alternative names");
                return null;
            }
        } catch (final Exception ioe) { // catch all exception here since BC throws diff exceptions
            throw new RuntimeException("Couldn't parse subject alternative names", ioe);
        }
    }
}
