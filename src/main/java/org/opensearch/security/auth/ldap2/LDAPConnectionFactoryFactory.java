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

package org.opensearch.security.auth.ldap2;

import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.PemKeyReader;

import org.ldaptive.ActivePassiveConnectionStrategy;
import org.ldaptive.BindConnectionInitializer;
import org.ldaptive.CompareRequest;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.Credential;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.FilterTemplate;
import org.ldaptive.PooledConnectionFactory;
import org.ldaptive.RandomConnectionStrategy;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.RoundRobinConnectionStrategy;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchScope;
import org.ldaptive.sasl.Mechanism;
import org.ldaptive.sasl.SaslConfig;
import org.ldaptive.ssl.AllowAnyHostnameVerifier;
import org.ldaptive.ssl.AllowAnyTrustManager;
import org.ldaptive.ssl.CredentialConfig;
import org.ldaptive.ssl.CredentialConfigFactory;
import org.ldaptive.ssl.SslConfig;

import static org.opensearch.security.setting.DeprecatedSettings.checkForDeprecatedSetting;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD;

public class LDAPConnectionFactoryFactory {

    private static final Logger log = LogManager.getLogger(LDAPConnectionFactoryFactory.class);
    private static final List<String> DEFAULT_TLS_PROTOCOLS = Arrays.asList("TLSv1.2", "TLSv1.3");

    private final Settings settings;
    private final Path configPath;

    public LDAPConnectionFactoryFactory(Settings settings, Path configPath) {
        this.settings = settings;
        this.configPath = configPath;
    }

    public ConnectionFactory createConnectionFactory(PooledConnectionFactory pooledConnectionFactory) {
        if (pooledConnectionFactory != null) {
            return pooledConnectionFactory;
        } else {
            return createBasicConnectionFactory();
        }
    }

    public DefaultConnectionFactory createBasicConnectionFactory() {
        return new DefaultConnectionFactory(getConnectionConfig());
    }

    public PooledConnectionFactory createPooledConnectionFactory() {
        if (!this.settings.getAsBoolean(ConfigConstants.LDAP_POOL_ENABLED, false)) {
            return null;
        }

        checkForDeprecatedSetting(settings, ConfigConstants.LDAP_LEGACY_POOL_PRUNING_PERIOD, ConfigConstants.LDAP_POOL_PRUNING_PERIOD);
        checkForDeprecatedSetting(settings, ConfigConstants.LDAP_LEGACY_POOL_IDLE_TIME, ConfigConstants.LDAP_POOL_IDLE_TIME);

        PooledConnectionFactory pooledConnectionFactory = PooledConnectionFactory.builder()
            .config(getConnectionConfig())
            .min(this.settings.getAsInt(ConfigConstants.LDAP_POOL_MIN_SIZE, 3))
            .max(this.settings.getAsInt(ConfigConstants.LDAP_POOL_MAX_SIZE, 10))
            .validator(getConnectionValidator())
            .build();

        pooledConnectionFactory.initialize();

        return pooledConnectionFactory;
    }

    private ConnectionConfig getConnectionConfig() {
        ConnectionConfig.Builder builder = ConnectionConfig.builder()
            .url(getLdapUrlString())
            .connectionStrategy(getConnectionStrategy())
            .connectionInitializers(getConnectionInitializer());

        long connectTimeout = settings.getAsLong(ConfigConstants.LDAP_CONNECT_TIMEOUT, 5000L);
        long responseTimeout = settings.getAsLong(ConfigConstants.LDAP_RESPONSE_TIMEOUT, 0L);

        builder.connectTimeout(Duration.ofMillis(connectTimeout < 0L ? 0L : connectTimeout));
        builder.responseTimeout(Duration.ofMillis(responseTimeout < 0L ? 0L : responseTimeout));

        try {
            configureSSL(builder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to configure SSL for LDAP", e);
        }

        ConnectionConfig result = builder.build();

        if (log.isDebugEnabled()) {
            log.debug("LDAP connection config:\n" + result);
        }

        return result;
    }

    private BindConnectionInitializer getConnectionInitializer() {
        String bindDn = settings.get(ConfigConstants.LDAP_BIND_DN, null);
        String password = settings.get(ConfigConstants.LDAP_PASSWORD, null);

        if (password != null && password.length() == 0) {
            password = null;
        }

        if (log.isDebugEnabled()) {
            log.debug("bindDn {}, password {}", bindDn, password != null ? "****" : "<not set>");
        }

        if (bindDn != null && password == null) {
            log.error("No password given for bind_dn {}. Will try to authenticate anonymously to ldap", bindDn);
        }

        boolean enableClientAuth = settings.getAsBoolean(
            ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH,
            ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH_DEFAULT
        );

        BindConnectionInitializer.Builder initBuilder = BindConnectionInitializer.builder();

        if (bindDn != null && password != null) {
            log.debug("Will perform simple bind with bind dn");
            initBuilder.dn(bindDn).credential(new Credential(password));

            if (enableClientAuth) {
                log.warn("Will perform simple bind with bind dn because bind dn is given and overrides client cert authentication");
            }
        } else if (enableClientAuth) {
            log.debug("Will perform External SASL bind because client cert authentication is enabled");
            initBuilder.saslConfig(SaslConfig.builder().mechanism(Mechanism.EXTERNAL).build());
        } else {
            log.debug("Will perform anonymous bind because no bind dn or password is given");
        }

        return initBuilder.build();
    }

    private org.ldaptive.ConnectionStrategy getConnectionStrategy() {
        switch (this.settings.get(ConfigConstants.LDAP_CONNECTION_STRATEGY, "active_passive").toLowerCase()) {
            case "round_robin":
                return new RoundRobinConnectionStrategy();
            case "random":
                return new RandomConnectionStrategy();
            default:
                return new ActivePassiveConnectionStrategy();
        }
    }

    private org.ldaptive.ConnectionValidator getConnectionValidator() {
        if (!this.settings.getAsBoolean("validation.enabled", false)) {
            return null;
        }

        String validationStrategy = this.settings.get("validation.strategy", "search");

        if ("compare".equalsIgnoreCase(validationStrategy)) {
            CompareRequest compareRequest = CompareRequest.builder()
                .dn(this.settings.get("validation.compare.dn", ""))
                .name(this.settings.get("validation.compare.attribute", "objectClass"))
                .value(this.settings.get("validation.compare.value", "top"))
                .build();
            return new org.ldaptive.CompareConnectionValidator(compareRequest);
        } else {
            SearchRequest searchRequest = SearchRequest.builder()
                .dn(this.settings.get("validation.search.base_dn", ""))
                .filter(FilterTemplate.builder().filter(this.settings.get("validation.search.filter", "(objectClass=*)")).build())
                .returnAttributes(ReturnAttributes.NONE.value())
                .scope(SearchScope.OBJECT)
                .sizeLimit(1)
                .build();
            return new org.ldaptive.SearchConnectionValidator(searchRequest);
        }
    }

    private String getLdapUrlString() {
        List<String> ldapHosts = this.settings.getAsList(ConfigConstants.LDAP_HOSTS, Collections.singletonList("localhost"));
        boolean enableSSL = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL, false);

        StringBuilder result = new StringBuilder();

        for (String ldapHost : ldapHosts) {
            if (result.length() > 0) {
                result.append(" ");
            }

            if (ldapHost.contains("://")) {
                result.append(ldapHost);
            } else if (enableSSL) {
                result.append("ldaps://").append(ldapHost);
            } else {
                result.append("ldap://").append(ldapHost);
            }
        }

        return result.toString();
    }

    private void configureSSL(ConnectionConfig.Builder builder) throws Exception {
        final boolean enableSSL = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL, false);
        final boolean enableStartTLS = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_START_TLS, false);

        if (!enableSSL && !enableStartTLS) {
            return;
        }

        final boolean enableClientAuth = settings.getAsBoolean(
            ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH,
            ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH_DEFAULT
        );
        final boolean trustAll = settings.getAsBoolean(ConfigConstants.LDAPS_TRUST_ALL, false);
        final boolean verifyHostnames = !trustAll
            && settings.getAsBoolean(ConfigConstants.LDAPS_VERIFY_HOSTNAMES, ConfigConstants.LDAPS_VERIFY_HOSTNAMES_DEFAULT);

        final boolean pem = settings.get(ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH, null) != null
            || settings.get(ConfigConstants.LDAPS_PEMTRUSTEDCAS_CONTENT, null) != null;

        SslConfig sslConfig = new SslConfig();

        if (pem) {
            X509Certificate[] trustCerts = PemKeyReader.loadCertificatesFromStream(
                PemKeyReader.resolveStream(ConfigConstants.LDAPS_PEMTRUSTEDCAS_CONTENT, settings)
            );
            if (trustCerts == null) {
                trustCerts = PemKeyReader.loadCertificatesFromFile(
                    PemKeyReader.resolve(ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH, settings, configPath, !trustAll)
                );
            }

            X509Certificate authCert = PemKeyReader.loadCertificateFromStream(
                PemKeyReader.resolveStream(ConfigConstants.LDAPS_PEMCERT_CONTENT, settings)
            );
            if (authCert == null) {
                authCert = PemKeyReader.loadCertificateFromFile(
                    PemKeyReader.resolve(ConfigConstants.LDAPS_PEMCERT_FILEPATH, settings, configPath, enableClientAuth)
                );
            }

            PrivateKey authKey = PemKeyReader.loadKeyFromStream(
                settings.get(ConfigConstants.LDAPS_PEMKEY_PASSWORD),
                PemKeyReader.resolveStream(ConfigConstants.LDAPS_PEMKEY_CONTENT, settings)
            );
            if (authKey == null) {
                authKey = PemKeyReader.loadKeyFromFile(
                    settings.get(ConfigConstants.LDAPS_PEMKEY_PASSWORD),
                    PemKeyReader.resolve(ConfigConstants.LDAPS_PEMKEY_FILEPATH, settings, configPath, enableClientAuth)
                );
            }

            CredentialConfig cc = CredentialConfigFactory.createX509CredentialConfig(trustCerts, authCert, authKey);
            sslConfig.setCredentialConfig(cc);
        } else {
            KeyStore trustStore = PemKeyReader.loadKeyStore(
                PemKeyReader.resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, settings, configPath, !trustAll),
                SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD.getSetting(settings),
                settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE)
            );

            KeyStore keyStore = PemKeyReader.loadKeyStore(
                PemKeyReader.resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, settings, configPath, enableClientAuth),
                SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD.getSetting(settings, SSLConfigConstants.DEFAULT_STORE_PASSWORD),
                settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE)
            );

            String keyStorePassword = SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD.getSetting(
                settings,
                SSLConfigConstants.DEFAULT_STORE_PASSWORD
            );
            List<String> trustAliases = settings.getAsList(ConfigConstants.LDAPS_JKS_TRUST_ALIAS, null);
            String keyAlias = settings.get(ConfigConstants.LDAPS_JKS_CERT_ALIAS, null);

            CredentialConfig cc = CredentialConfigFactory.createKeyStoreCredentialConfig(
                trustStore,
                trustAliases != null ? trustAliases.toArray(new String[0]) : null,
                keyStore,
                keyStorePassword,
                keyAlias != null ? new String[] { keyAlias } : null
            );
            sslConfig.setCredentialConfig(cc);
        }

        if (trustAll) {
            sslConfig.setTrustManagers(new AllowAnyTrustManager());
        }
        if (!verifyHostnames) {
            sslConfig.setHostnameVerifier(new AllowAnyHostnameVerifier());
        }

        List<String> ciphers = settings.getAsList(ConfigConstants.LDAPS_ENABLED_SSL_CIPHERS, Collections.emptyList());
        if (!ciphers.isEmpty()) {
            sslConfig.setEnabledCipherSuites(ciphers.toArray(new String[0]));
        }

        List<String> protocols = settings.getAsList(ConfigConstants.LDAPS_ENABLED_SSL_PROTOCOLS, DEFAULT_TLS_PROTOCOLS);
        sslConfig.setEnabledProtocols(protocols.toArray(new String[0]));

        builder.sslConfig(sslConfig);
        builder.useStartTLS(enableStartTLS);
    }
}
