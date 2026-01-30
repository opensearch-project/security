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
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.util.SettingsBasedSSLConfigurator;
import org.opensearch.security.util.SettingsBasedSSLConfigurator.SSLConfigException;

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
import org.ldaptive.ssl.DefaultSSLContextInitializer;
import org.ldaptive.ssl.SslConfig;

import static org.opensearch.security.setting.DeprecatedSettings.checkForDeprecatedSetting;

public class LDAPConnectionFactoryFactory {

    private static final Logger log = LogManager.getLogger(LDAPConnectionFactoryFactory.class);

    private final Settings settings;
    private final SettingsBasedSSLConfigurator.SSLConfig sslConfig;

    public LDAPConnectionFactoryFactory(Settings settings, Path configPath) throws SSLConfigException {
        this.settings = settings;
        this.sslConfig = new SettingsBasedSSLConfigurator(settings, configPath, "").buildSSLConfig();
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

        if (this.sslConfig != null) {
            configureSSL(builder);
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

    private void configureSSL(ConnectionConfig.Builder builder) {
        if (this.sslConfig == null) {
            return;
        }

        SslConfig ldaptiveSslConfig = new SslConfig();

        KeyStore trustStore = this.sslConfig.getEffectiveTruststore();
        KeyStore keyStore = this.sslConfig.getEffectiveKeystore();
        String keyPassword = this.sslConfig.getEffectiveKeyPasswordString();

        try {
            TrustManagerFactory tmf = null;
            KeyManagerFactory kmf = null;

            if (trustStore != null) {
                tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStore);
            }
            if (keyStore != null) {
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keyStore, keyPassword != null ? keyPassword.toCharArray() : null);
            }

            if (tmf != null || kmf != null) {
                if (tmf != null) {
                    ldaptiveSslConfig.setTrustManagers(tmf.getTrustManagers());
                }
                if (kmf != null) {
                    ldaptiveSslConfig.setCredentialConfig(createCredentialConfig(kmf.getKeyManagers()));
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to configure SSL for LDAP", e);
        }

        if (!this.sslConfig.isHostnameVerificationEnabled()) {
            ldaptiveSslConfig.setHostnameVerifier(new AllowAnyHostnameVerifier());
        }

        if (this.sslConfig.getSupportedCipherSuites() != null && this.sslConfig.getSupportedCipherSuites().length > 0) {
            ldaptiveSslConfig.setEnabledCipherSuites(this.sslConfig.getSupportedCipherSuites());
        }

        ldaptiveSslConfig.setEnabledProtocols(this.sslConfig.getSupportedProtocols());

        if (this.sslConfig.isTrustAllEnabled()) {
            ldaptiveSslConfig.setTrustManagers(new AllowAnyTrustManager());
        }

        builder.sslConfig(ldaptiveSslConfig);
        builder.useStartTLS(this.sslConfig.isStartTlsEnabled());
    }

    private static CredentialConfig createCredentialConfig(KeyManager[] keyManagers) {
        return () -> {
            DefaultSSLContextInitializer init = new DefaultSSLContextInitializer();
            init.setKeyManagers(keyManagers);
            return init;
        };
    }
}
