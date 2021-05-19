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

package com.amazon.dlic.util;

import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;

import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.PemKeyReader;
import com.google.common.collect.ImmutableList;

public class SettingsBasedSSLConfigurator {
    private static final Logger log = LogManager.getLogger(SettingsBasedSSLConfigurator.class);

    public static final String CERT_ALIAS = "cert_alias";
    public static final String CA_ALIAS = "ca_alias";
    public static final String ENABLE_SSL = "enable_ssl";

    /**
     * Shall STARTTLS shall be used?
     * <p>
     * NOTE: The setting of this option is only reflected by the startTlsEnabled
     * attribute of the returned SSLConfig object. Clients of this class need to
     * take further measures to enable STARTTLS. It does not affect the
     * SSLIOSessionStrategy and SSLConnectionSocketFactory objects returned from
     * this class.
     */
    public static final String ENABLE_START_TLS = "enable_start_tls";
    public static final String ENABLE_SSL_CLIENT_AUTH = "enable_ssl_client_auth";
    public static final String PEMKEY_FILEPATH = "pemkey_filepath";
    public static final String PEMKEY_CONTENT = "pemkey_content";
    public static final String PEMKEY_PASSWORD = "pemkey_password";
    public static final String PEMCERT_FILEPATH = "pemcert_filepath";
    public static final String PEMCERT_CONTENT = "pemcert_content";
    public static final String PEMTRUSTEDCAS_CONTENT = "pemtrustedcas_content";
    public static final String PEMTRUSTEDCAS_FILEPATH = "pemtrustedcas_filepath";
    public static final String VERIFY_HOSTNAMES = "verify_hostnames";
    public static final String TRUST_ALL = "trust_all";

    private static final List<String> DEFAULT_TLS_PROTOCOLS = ImmutableList.of("TLSv1.2", "TLSv1.1");

    private SSLContextBuilder sslContextBuilder;
    private final Settings settings;
    private final String settingsKeyPrefix;
    private final Path configPath;
    private final String clientName;

    private boolean enabled;
    private boolean enableSslClientAuth;
    private KeyStore effectiveTruststore;
    private KeyStore effectiveKeystore;
    private char[] effectiveKeyPassword;
    private String effectiveKeyAlias;
    private List<String> effectiveTruststoreAliases;

    public SettingsBasedSSLConfigurator(Settings settings, Path configPath, String settingsKeyPrefix,
            String clientName) {
        this.settings = settings;
        this.configPath = configPath;
        this.settingsKeyPrefix = normalizeSettingsKeyPrefix(settingsKeyPrefix);
        this.clientName = clientName != null ? clientName : this.settingsKeyPrefix;
    }

    public SettingsBasedSSLConfigurator(Settings settings, Path configPath, String settingsKeyPrefix) {
        this(settings, configPath, settingsKeyPrefix, null);
    }

    SSLContext buildSSLContext() throws SSLConfigException {
        try {
            if (isTrustAllEnabled()) {
                sslContextBuilder = new OverlyTrustfulSSLContextBuilder();
            } else {
                sslContextBuilder = SSLContexts.custom();
            }

            configureWithSettings();

            if (!this.enabled) {
                return null;
            }

            return sslContextBuilder.build();

        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw new SSLConfigException("Error while initializing SSL configuration for " + this.clientName, e);
        }
    }

    public SSLConfig buildSSLConfig() throws SSLConfigException {
        SSLContext sslContext = buildSSLContext();

        if (sslContext == null) {
            // disabled
            return null;
        }

        return new SSLConfig(sslContext, getSupportedProtocols(), getSupportedCipherSuites(), getHostnameVerifier(),
                isHostnameVerificationEnabled(), isTrustAllEnabled(), isStartTlsEnabled(), this.effectiveTruststore,
                this.effectiveTruststoreAliases, this.effectiveKeystore, this.effectiveKeyPassword,
                this.effectiveKeyAlias);
    }

    private boolean isHostnameVerificationEnabled() {
        return getSettingAsBoolean(VERIFY_HOSTNAMES, true) && !isTrustAllEnabled();
    }

    private HostnameVerifier getHostnameVerifier() {
        if (isHostnameVerificationEnabled()) {
            return new DefaultHostnameVerifier();
        } else {
            return NoopHostnameVerifier.INSTANCE;
        }
    }

    private String[] getSupportedProtocols() {
        return getSettingAsArray("enabled_ssl_protocols", DEFAULT_TLS_PROTOCOLS);
    }

    private String[] getSupportedCipherSuites() {
        return getSettingAsArray("enabled_ssl_ciphers", null);

    }

    private boolean isStartTlsEnabled() {
        return getSettingAsBoolean(ENABLE_START_TLS, false);
    }

    private boolean isTrustAllEnabled() {
        return getSettingAsBoolean(TRUST_ALL, false);
    }

    private void configureWithSettings() throws SSLConfigException, NoSuchAlgorithmException, KeyStoreException {
        this.enabled = getSettingAsBoolean(ENABLE_SSL, false);

        if (!this.enabled) {
            return;
        }

        this.enableSslClientAuth = getSettingAsBoolean(ENABLE_SSL_CLIENT_AUTH, false);

        if (settings.get(settingsKeyPrefix + PEMTRUSTEDCAS_FILEPATH, null) != null
                || settings.get(settingsKeyPrefix + PEMTRUSTEDCAS_CONTENT, null) != null) {
            initFromPem();
        } else {
            initFromKeyStore();
        }

        if (effectiveTruststore != null) {
            sslContextBuilder.loadTrustMaterial(effectiveTruststore, null);
        }

        if (enableSslClientAuth) {
            if (effectiveKeystore != null) {
                try {
                    sslContextBuilder.loadKeyMaterial(effectiveKeystore, effectiveKeyPassword,
                            new PrivateKeyStrategy() {

                                @Override
                                public String chooseAlias(Map<String, PrivateKeyDetails> aliases, Socket socket) {
                                    if (aliases == null || aliases.isEmpty()) {
                                        return effectiveKeyAlias;
                                    }

                                    if (effectiveKeyAlias == null || effectiveKeyAlias.isEmpty()) {
                                        return aliases.keySet().iterator().next();
                                    }

                                    return effectiveKeyAlias;
                                }
                            });
                } catch (UnrecoverableKeyException e) {
                    throw new RuntimeException(e);
                }
            }
        }

    }

    private void initFromPem() throws SSLConfigException {
        X509Certificate[] trustCertificates;

        try {
            trustCertificates = PemKeyReader.loadCertificatesFromStream(
                    PemKeyReader.resolveStream(settingsKeyPrefix + PEMTRUSTEDCAS_CONTENT, settings));
        } catch (Exception e) {
            throw new SSLConfigException(
                    "Error loading PEM from " + settingsKeyPrefix + PEMTRUSTEDCAS_CONTENT + " for " + this.clientName,
                    e);
        }

        if (trustCertificates == null) {
            String path = PemKeyReader.resolve(settingsKeyPrefix + PEMTRUSTEDCAS_FILEPATH, settings, configPath,
                    !isTrustAllEnabled());

            try {
                trustCertificates = PemKeyReader.loadCertificatesFromFile(path);
            } catch (Exception e) {
                throw new SSLConfigException("Error loading PEM from " + path + " (" + settingsKeyPrefix
                        + PEMTRUSTEDCAS_FILEPATH + ") for " + this.clientName, e);
            }
        }

        // for client authentication
        X509Certificate[] authenticationCertificate;

        try {
            authenticationCertificate = PemKeyReader.loadCertificatesFromStream(
                    PemKeyReader.resolveStream(settingsKeyPrefix + PEMCERT_CONTENT, settings));
        } catch (Exception e) {
            throw new SSLConfigException(
                    "Error loading PEM from " + settingsKeyPrefix + PEMCERT_CONTENT + " for " + this.clientName, e);
        }

        if (authenticationCertificate == null) {
            String path = PemKeyReader.resolve(settingsKeyPrefix + PEMCERT_FILEPATH, settings, configPath,
                    enableSslClientAuth);

            try {
                authenticationCertificate = PemKeyReader.loadCertificatesFromFile(path);
            } catch (Exception e) {
                throw new SSLConfigException("Error loading PEM from " + path + " (" + settingsKeyPrefix
                        + PEMCERT_FILEPATH + ") for " + this.clientName, e);
            }

        }

        PrivateKey authenticationKey;

        try {
            authenticationKey = PemKeyReader.loadKeyFromStream(getSetting(PEMKEY_PASSWORD),
                    PemKeyReader.resolveStream(settingsKeyPrefix + PEMKEY_CONTENT, settings));
        } catch (Exception e) {
            throw new SSLConfigException(
                    "Error loading PEM from " + settingsKeyPrefix + PEMKEY_CONTENT + " for " + this.clientName, e);
        }

        if (authenticationKey == null) {
            String path = PemKeyReader.resolve(settingsKeyPrefix + PEMKEY_FILEPATH, settings, configPath,
                    enableSslClientAuth);

            try {
                authenticationKey = PemKeyReader.loadKeyFromFile(getSetting(PEMKEY_PASSWORD), path);
            } catch (Exception e) {
                throw new SSLConfigException("Error loading PEM from " + path + " (" + settingsKeyPrefix
                        + PEMKEY_FILEPATH + ") for " + this.clientName, e);
            }
        }

        try {
            effectiveKeyPassword = PemKeyReader.randomChars(12);
            effectiveKeyAlias = "al";
            effectiveTruststore = PemKeyReader.toTruststore(effectiveKeyAlias, trustCertificates);
            effectiveKeystore = PemKeyReader.toKeystore(effectiveKeyAlias, effectiveKeyPassword,
                    authenticationCertificate, authenticationKey);
        } catch (Exception e) {
            throw new SSLConfigException("Error initializing SSLConfig for " + this.clientName, e);
        }

    }

    private void initFromKeyStore() throws SSLConfigException {
        KeyStore trustStore;
        KeyStore keyStore;

        try {
            trustStore = PemKeyReader.loadKeyStore(
                    PemKeyReader.resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, settings,
                            configPath, !isTrustAllEnabled()),
                    settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD,
                            SSLConfigConstants.DEFAULT_STORE_PASSWORD),
                    settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE));
        } catch (Exception e) {
            throw new SSLConfigException("Error loading trust store from "
                    + settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH), e);
        }

        effectiveTruststoreAliases = getSettingAsList(CA_ALIAS, null);

        // for client authentication

        try {
            keyStore = PemKeyReader.loadKeyStore(
                    PemKeyReader.resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, settings,
                            configPath, enableSslClientAuth),
                    settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD,
                            SSLConfigConstants.DEFAULT_STORE_PASSWORD),
                    settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE));
        } catch (Exception e) {
            throw new SSLConfigException("Error loading key store from "
                    + settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH), e);
        }

        String keyStorePassword = settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD,
                SSLConfigConstants.DEFAULT_STORE_PASSWORD);
        effectiveKeyPassword = keyStorePassword == null || keyStorePassword.isEmpty() ? null
                : keyStorePassword.toCharArray();
        effectiveKeyAlias = getSetting(CERT_ALIAS);

        if (enableSslClientAuth && effectiveKeyAlias == null) {
            throw new IllegalArgumentException(settingsKeyPrefix + CERT_ALIAS + " not given");
        }

        effectiveTruststore = trustStore;
        effectiveKeystore = keyStore;

    }

    private String getSetting(String key) {
        return settings.get(settingsKeyPrefix + key);
    }

    private Boolean getSettingAsBoolean(String key, Boolean defaultValue) {
        return settings.getAsBoolean(settingsKeyPrefix + key, defaultValue);
    }

    private List<String> getSettingAsList(String key, List<String> defaultValue) {
        return settings.getAsList(settingsKeyPrefix + key, defaultValue);
    }

    private String[] getSettingAsArray(String key, List<String> defaultValue) {
        List<String> list = getSettingAsList(key, defaultValue);

        if (list == null) {
            return null;
        }

        return list.toArray(new String[list.size()]);
    }

    private static String normalizeSettingsKeyPrefix(String settingsKeyPrefix) {
        if (settingsKeyPrefix == null || settingsKeyPrefix.length() == 0) {
            return "";
        } else if (!settingsKeyPrefix.endsWith(".")) {
            return settingsKeyPrefix + ".";
        } else {
            return settingsKeyPrefix;
        }
    }

    public static class SSLConfig {

        private final SSLContext sslContext;
        private final String[] supportedProtocols;
        private final String[] supportedCipherSuites;
        private final HostnameVerifier hostnameVerifier;
        private final boolean startTlsEnabled;
        private final boolean hostnameVerificationEnabled;
        private final boolean trustAll;
        private final KeyStore effectiveTruststore;
        private final List<String> effectiveTruststoreAliases;
        private final KeyStore effectiveKeystore;
        private final char[] effectiveKeyPassword;
        private final String effectiveKeyAlias;

        public SSLConfig(SSLContext sslContext, String[] supportedProtocols, String[] supportedCipherSuites,
                HostnameVerifier hostnameVerifier, boolean hostnameVerificationEnabled, boolean trustAll,
                boolean startTlsEnabled, KeyStore effectiveTruststore, List<String> effectiveTruststoreAliases,
                KeyStore effectiveKeystore, char[] effectiveKeyPassword, String effectiveKeyAlias) {
            this.sslContext = sslContext;
            this.supportedProtocols = supportedProtocols;
            this.supportedCipherSuites = supportedCipherSuites;
            this.hostnameVerifier = hostnameVerifier;
            this.hostnameVerificationEnabled = hostnameVerificationEnabled;
            this.trustAll = trustAll;
            this.startTlsEnabled = startTlsEnabled;
            this.effectiveTruststore = effectiveTruststore;
            this.effectiveTruststoreAliases = effectiveTruststoreAliases;
            this.effectiveKeystore = effectiveKeystore;
            this.effectiveKeyPassword = effectiveKeyPassword;
            this.effectiveKeyAlias = effectiveKeyAlias;

            if (log.isDebugEnabled()) {
                log.debug("Created SSLConfig: {}", this);
            }
        }

        public SSLContext getSslContext() {
            return sslContext;
        }

        public String[] getSupportedProtocols() {
            return supportedProtocols;
        }

        public String[] getSupportedCipherSuites() {
            return supportedCipherSuites;
        }

        public HostnameVerifier getHostnameVerifier() {
            return hostnameVerifier;
        }

        public SSLIOSessionStrategy toSSLIOSessionStrategy() {
            return new SSLIOSessionStrategy(sslContext, supportedProtocols, supportedCipherSuites, hostnameVerifier);
        }

        public SSLConnectionSocketFactory toSSLConnectionSocketFactory() {
            return new SSLConnectionSocketFactory(sslContext, supportedProtocols, supportedCipherSuites,
                    hostnameVerifier);
        }

        public boolean isStartTlsEnabled() {
            return startTlsEnabled;
        }

        public boolean isHostnameVerificationEnabled() {
            return hostnameVerificationEnabled;
        }

        public KeyStore getEffectiveTruststore() {
            return effectiveTruststore;
        }

        public KeyStore getEffectiveKeystore() {
            return effectiveKeystore;
        }

        public char[] getEffectiveKeyPassword() {
            return effectiveKeyPassword;
        }

        public String getEffectiveKeyPasswordString() {
            if (this.effectiveKeyPassword == null) {
                return null;
            } else {
                return new String(this.effectiveKeyPassword);
            }
        }

        public String getEffectiveKeyAlias() {
            return effectiveKeyAlias;
        }

        public List<String> getEffectiveTruststoreAliases() {
            return effectiveTruststoreAliases;
        }

        public String[] getEffectiveTruststoreAliasesArray() {
            if (this.effectiveTruststoreAliases == null) {
                return null;
            } else {
                return this.effectiveTruststoreAliases.toArray(new String[this.effectiveTruststoreAliases.size()]);
            }
        }

        public String[] getEffectiveKeyAliasesArray() {
            if (this.effectiveKeyAlias == null) {
                return null;
            } else {
                return new String[] { this.effectiveKeyAlias };
            }
        }

        @Override
        public String toString() {
            return "SSLConfig [sslContext=" + sslContext + ", supportedProtocols=" + Arrays.toString(supportedProtocols)
                    + ", supportedCipherSuites=" + Arrays.toString(supportedCipherSuites) + ", hostnameVerifier="
                    + hostnameVerifier + ", startTlsEnabled=" + startTlsEnabled + ", hostnameVerificationEnabled="
                    + hostnameVerificationEnabled + ", trustAll=" + trustAll + ", effectiveTruststore="
                    + effectiveTruststore + ", effectiveTruststoreAliases=" + effectiveTruststoreAliases
                    + ", effectiveKeystore=" + effectiveKeystore + ", effectiveKeyAlias=" + effectiveKeyAlias + "]";
        }

        public boolean isTrustAllEnabled() {
            return trustAll;
        }
    }

    public static class SSLConfigException extends Exception {

        private static final long serialVersionUID = 5827273100470174111L;

        public SSLConfigException() {
            super();
        }

        public SSLConfigException(String message, Throwable cause, boolean enableSuppression,
                boolean writableStackTrace) {
            super(message, cause, enableSuppression, writableStackTrace);
        }

        public SSLConfigException(String message, Throwable cause) {
            super(message, cause);
        }

        public SSLConfigException(String message) {
            super(message);
        }

        public SSLConfigException(Throwable cause) {
            super(cause);
        }

    }

    private static class OverlyTrustfulSSLContextBuilder extends SSLContextBuilder {
        @Override
        protected void initSSLContext(SSLContext sslContext, Collection<KeyManager> keyManagers,
                Collection<TrustManager> trustManagers, SecureRandom secureRandom) throws KeyManagementException {
            sslContext.init(!keyManagers.isEmpty() ? keyManagers.toArray(new KeyManager[keyManagers.size()]) : null,
                    new TrustManager[] { new OverlyTrustfulTrustManager() }, secureRandom);
        }
    }

    private static class OverlyTrustfulTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(final X509Certificate[] chain, final String authType)
                throws CertificateException {
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] chain, final String authType)
                throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
