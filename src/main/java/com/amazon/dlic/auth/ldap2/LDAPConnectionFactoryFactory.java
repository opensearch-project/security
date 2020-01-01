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

package com.amazon.dlic.auth.ldap2;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.ldaptive.ActivePassiveConnectionStrategy;
import org.ldaptive.BindConnectionInitializer;
import org.ldaptive.CompareRequest;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.ConnectionInitializer;
import org.ldaptive.ConnectionStrategy;
import org.ldaptive.Credential;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.RandomConnectionStrategy;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.RoundRobinConnectionStrategy;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchScope;
import org.ldaptive.pool.AbstractConnectionPool;
import org.ldaptive.pool.BlockingConnectionPool;
import org.ldaptive.pool.CompareValidator;
import org.ldaptive.pool.ConnectionPool;
import org.ldaptive.pool.IdlePruneStrategy;
import org.ldaptive.pool.PoolConfig;
import org.ldaptive.pool.PooledConnectionFactory;
import org.ldaptive.pool.SearchValidator;
import org.ldaptive.pool.SoftLimitConnectionPool;
import org.ldaptive.pool.Validator;
import org.ldaptive.provider.Provider;
import org.ldaptive.provider.jndi.JndiProviderConfig;
import org.ldaptive.sasl.ExternalConfig;
import org.ldaptive.ssl.AllowAnyHostnameVerifier;
import org.ldaptive.ssl.AllowAnyTrustManager;
import org.ldaptive.ssl.CredentialConfig;
import org.ldaptive.ssl.CredentialConfigFactory;
import org.ldaptive.ssl.SslConfig;

import com.amazon.dlic.auth.ldap.util.ConfigConstants;
import com.amazon.dlic.util.SettingsBasedSSLConfigurator;
import com.amazon.dlic.util.SettingsBasedSSLConfigurator.SSLConfigException;

public class LDAPConnectionFactoryFactory {

    private static final Logger log = LogManager.getLogger(LDAPConnectionFactoryFactory.class);

    private final Settings settings;
    private final SettingsBasedSSLConfigurator.SSLConfig sslConfig;

    public LDAPConnectionFactoryFactory(Settings settings, Path configPath) throws SSLConfigException {
        this.settings = settings;
        this.sslConfig = new SettingsBasedSSLConfigurator(settings, configPath, "").buildSSLConfig();
    }

    public ConnectionFactory createConnectionFactory(ConnectionPool connectionPool) {
        if (connectionPool != null) {
            return new PooledConnectionFactory(connectionPool);
        } else {
            return createBasicConnectionFactory();
        }
    }

    @SuppressWarnings("unchecked")
    public DefaultConnectionFactory createBasicConnectionFactory() {
        DefaultConnectionFactory result = new DefaultConnectionFactory(getConnectionConfig());

        result.setProvider(new PrivilegedProvider((Provider<JndiProviderConfig>) result.getProvider()));

        JndiProviderConfig jndiProviderConfig = (JndiProviderConfig) result.getProvider().getProviderConfig();

        jndiProviderConfig.setClassLoader(MakeJava9Happy.getClassLoader());

        if (this.sslConfig != null) {
            configureSSLinConnectionFactory(result);
        }

        return result;
    }

    public ConnectionPool createConnectionPool() {

        if (!this.settings.getAsBoolean(ConfigConstants.LDAP_POOL_ENABLED, false)) {
            return null;
        }

        PoolConfig poolConfig = new PoolConfig();

        poolConfig.setMinPoolSize(this.settings.getAsInt(ConfigConstants.LDAP_POOL_MIN_SIZE, 3));
        poolConfig.setMaxPoolSize(this.settings.getAsInt(ConfigConstants.LDAP_POOL_MAX_SIZE, 10));

        if (this.settings.getAsBoolean("validation.enabled", false)) {
            poolConfig.setValidateOnCheckIn(this.settings.getAsBoolean("validation.on_checkin", false));
            poolConfig.setValidateOnCheckOut(this.settings.getAsBoolean("validation.on_checkout", false));
            poolConfig.setValidatePeriodically(this.settings.getAsBoolean("validation.periodically", true));
            poolConfig.setValidatePeriod(Duration.ofMinutes(this.settings.getAsLong("validation.period", 30l)));
            poolConfig.setValidateTimeout(Duration.ofSeconds(this.settings.getAsLong("validation.timeout", 5l)));
        }

        AbstractConnectionPool result;

        if ("blocking".equals(this.settings.get(ConfigConstants.LDAP_POOL_TYPE))) {
            result = new BlockingConnectionPool(poolConfig, createBasicConnectionFactory());
        } else {
            result = new SoftLimitConnectionPool(poolConfig, createBasicConnectionFactory());
        }

        result.setValidator(getConnectionValidator());
        result.setPruneStrategy(new IdlePruneStrategy(Duration.ofMinutes(this.settings.getAsLong("pruning.period", 5l)),
                Duration.ofMinutes(this.settings.getAsLong("pruning.idleTime", 10l))));

        result.initialize();

        return result;
    }

    private ConnectionConfig getConnectionConfig() {
        ConnectionConfig result = new ConnectionConfig(getLdapUrlString());

        if (this.sslConfig != null) {
            configureSSL(result);
        }

        result.setConnectionStrategy(getConnectionStrategy());
        result.setConnectionInitializer(getConnectionInitializer());

        long connectTimeout = settings.getAsLong(ConfigConstants.LDAP_CONNECT_TIMEOUT, 5000L); // 0L means TCP
        // default timeout
        long responseTimeout = settings.getAsLong(ConfigConstants.LDAP_RESPONSE_TIMEOUT, 0L); // 0L means wait
        // infinitely

        result.setConnectTimeout(Duration.ofMillis(connectTimeout < 0L ? 0L : connectTimeout)); // 5 sec by default
        result.setResponseTimeout(Duration.ofMillis(responseTimeout < 0L ? 0L : responseTimeout));

        if (log.isDebugEnabled()) {
            log.debug("LDAP connection config:\n" + result);
        }

        return result;
    }

    private ConnectionInitializer getConnectionInitializer() {
        BindConnectionInitializer result = new BindConnectionInitializer();

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

        boolean enableClientAuth = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH,
                ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH_DEFAULT);

        if (bindDn != null && password != null) {
            log.debug("Will perform simple bind with bind dn");
            result.setBindDn(bindDn);
            result.setBindCredential(new Credential(password));

            if (enableClientAuth) {
                log.warn(
                        "Will perform simple bind with bind dn because to bind dn is given and overrides client cert authentication");
            }
        } else if (enableClientAuth) {
            log.debug("Will perform External SASL bind because client cert authentication is enabled");
            result.setBindSaslConfig(new ExternalConfig());
        } else {
            log.debug("Will perform anonymous bind because no bind dn or password is given");
        }

        return result;
    }

    private ConnectionStrategy getConnectionStrategy() {
        switch (this.settings.get(ConfigConstants.LDAP_CONNECTION_STRATEGY, "active_passive").toLowerCase()) {
        case "round_robin":
            return new RoundRobinConnectionStrategy();
        case "random":
            return new RandomConnectionStrategy();
        default:
            return new ActivePassiveConnectionStrategy();
        }
    }

    private Validator<Connection> getConnectionValidator() {
        if (!this.settings.getAsBoolean("validation.enabled", false)) {
            return null;
        }

        String validationStrategy = this.settings.get("validation.strategy", "search");
        Validator<Connection> result = null;

        if ("compare".equalsIgnoreCase(validationStrategy)) {
            result = new CompareValidator(new CompareRequest(this.settings.get("validation.compare.dn", ""),
                    new LdapAttribute(this.settings.get("validation.compare.attribute", "objectClass"),
                            this.settings.get("validation.compare.value", "top"))));
        } else {
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.setBaseDn(this.settings.get("validation.search.base_dn", ""));
            searchRequest.setSearchFilter(
                    new SearchFilter(this.settings.get("validation.search.filter", "(objectClass=*)")));
            searchRequest.setReturnAttributes(ReturnAttributes.NONE.value());
            searchRequest.setSearchScope(SearchScope.OBJECT);
            searchRequest.setSizeLimit(1);

            result = new SearchValidator(searchRequest);
        }

        return result;
    }

    private String getLdapUrlString() {
        // It's a bit weird that we create from structured data a plain string which is
        // later parsed again by ldaptive. But that's the way the API wants it to be.

        List<String> ldapHosts = this.settings.getAsList(ConfigConstants.LDAP_HOSTS,
                Collections.singletonList("localhost"));
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

    private void configureSSL(ConnectionConfig config) {

        if (this.sslConfig == null) {
            // Disabled
            return;
        }

        SslConfig ldaptiveSslConfig = new SslConfig();
        CredentialConfig cc = CredentialConfigFactory.createKeyStoreCredentialConfig(
                this.sslConfig.getEffectiveTruststore(), this.sslConfig.getEffectiveTruststoreAliasesArray(),
                this.sslConfig.getEffectiveKeystore(), this.sslConfig.getEffectiveKeyPasswordString(),
                this.sslConfig.getEffectiveKeyAliasesArray());

        ldaptiveSslConfig.setCredentialConfig(cc);

        if (!this.sslConfig.isHostnameVerificationEnabled()) {
            ldaptiveSslConfig.setHostnameVerifier(new AllowAnyHostnameVerifier());

            if (!Boolean.parseBoolean(System.getProperty("com.sun.jndi.ldap.object.disableEndpointIdentification"))) {
                log.warn("In order to disable host name verification for LDAP connections (verify_hostnames: true), "
                        + "you also need to set set the system property com.sun.jndi.ldap.object.disableEndpointIdentification to true when starting the JVM running ES. "
                        + "This applies for all Java versions released since July 2018.");
                // See:
                // https://www.oracle.com/technetwork/java/javase/8u181-relnotes-4479407.html
                // https://www.oracle.com/technetwork/java/javase/10-0-2-relnotes-4477557.html
                // https://www.oracle.com/technetwork/java/javase/11-0-1-relnotes-5032023.html
            }
        }

        if (this.sslConfig.getSupportedCipherSuites() != null && this.sslConfig.getSupportedCipherSuites().length > 0) {
            ldaptiveSslConfig.setEnabledCipherSuites(this.sslConfig.getSupportedCipherSuites());
        }

        ldaptiveSslConfig.setEnabledProtocols(this.sslConfig.getSupportedProtocols());

        if (this.sslConfig.isTrustAllEnabled()) {
            ldaptiveSslConfig.setTrustManagers(new AllowAnyTrustManager());
        }

        config.setSslConfig(ldaptiveSslConfig);

        config.setUseSSL(true);
        config.setUseStartTLS(this.sslConfig.isStartTlsEnabled());

    }

    @SuppressWarnings("unchecked")
    private void configureSSLinConnectionFactory(DefaultConnectionFactory connectionFactory) {
        if (this.sslConfig == null) {
            // Disabled
            return;
        }

        Map<String, Object> props = new HashMap<String, Object>();

        if (this.sslConfig.isStartTlsEnabled() && !this.sslConfig.isHostnameVerificationEnabled()) {
            props.put("jndi.starttls.allowAnyHostname", "true");
        }

        connectionFactory.getProvider().getProviderConfig().setProperties(props);

    }
}
