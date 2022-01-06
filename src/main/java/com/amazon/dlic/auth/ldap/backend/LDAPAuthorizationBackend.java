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

package com.amazon.dlic.auth.ldap.backend;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.Strings;
import org.opensearch.common.settings.Settings;
import org.ldaptive.BindConnectionInitializer;
import org.ldaptive.BindRequest;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.Credential;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchScope;
import org.ldaptive.control.RequestControl;
import org.ldaptive.provider.ProviderConnection;
import org.ldaptive.provider.jndi.JndiConnection;
import org.ldaptive.sasl.Mechanism;
import org.ldaptive.sasl.SaslConfig;
import org.ldaptive.ssl.AllowAnyHostnameVerifier;
import org.ldaptive.ssl.AllowAnyTrustManager;
import org.ldaptive.ssl.CredentialConfig;
import org.ldaptive.ssl.CredentialConfigFactory;
import org.ldaptive.ssl.SslConfig;
import org.ldaptive.ssl.ThreadLocalTLSSocketFactory;

import com.amazon.dlic.auth.ldap.LdapUser;
import com.amazon.dlic.auth.ldap.util.ConfigConstants;
import com.amazon.dlic.auth.ldap.util.LdapHelper;
import com.amazon.dlic.auth.ldap.util.Utils;
import org.opensearch.security.auth.AuthorizationBackend;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.PemKeyReader;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import com.google.common.collect.HashMultimap;

import io.netty.util.internal.PlatformDependent;

public class LDAPAuthorizationBackend implements AuthorizationBackend {

    private static final AtomicInteger CONNECTION_COUNTER = new AtomicInteger();
    private static final String COM_SUN_JNDI_LDAP_OBJECT_DISABLE_ENDPOINT_IDENTIFICATION = "com.sun.jndi.ldap.object.disableEndpointIdentification";
    private static final List<String> DEFAULT_TLS_PROTOCOLS = Arrays.asList("TLSv1.2", "TLSv1.1");
    static final int ONE_PLACEHOLDER = 1;
    static final int TWO_PLACEHOLDER = 2;
    static final String DEFAULT_ROLEBASE = "";
    static final String DEFAULT_ROLESEARCH = "(member={0})";
    static final String DEFAULT_ROLENAME = "name";
    static final String DEFAULT_USERROLENAME = "memberOf";

    protected static final Logger log = LoggerFactory.getLogger(LDAPAuthorizationBackend.class);
    private final Settings settings;
    private final WildcardMatcher skipUsersMatcher;
    private final WildcardMatcher nestedRoleMatcher;

    private final Path configPath;
    private final List<Map.Entry<String, Settings>> roleBaseSettings;
    private final List<Map.Entry<String, Settings>> userBaseSettings;

    public LDAPAuthorizationBackend(final Settings settings, final Path configPath) {
        this.settings = settings;
        this.skipUsersMatcher = WildcardMatcher.from(settings.getAsList(ConfigConstants.LDAP_AUTHZ_SKIP_USERS));
        this.nestedRoleMatcher = settings.getAsBoolean(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false) ?
                WildcardMatcher.from(settings.getAsList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER)) : null;
        this.configPath = configPath;
        this.roleBaseSettings = getRoleSearchSettings(settings);
        this.userBaseSettings = LDAPAuthenticationBackend.getUserBaseSettings(settings);
    }

    public static void checkConnection(final ConnectionConfig connectionConfig, String bindDn, byte[] password) throws Exception {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                @Override
                public Void run() throws Exception {
                    boolean isJava9OrHigher = PlatformDependent.javaVersion() >= 9;
                    ClassLoader originalClassloader = null;
                    if (isJava9OrHigher) {
                        originalClassloader = Thread.currentThread().getContextClassLoader();
                        Thread.currentThread().setContextClassLoader(new Java9CL());
                    }

                    checkConnection0(connectionConfig, bindDn, password, originalClassloader, isJava9OrHigher);
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            throw e.getException();
        }

    }

    public static Connection getConnection(final Settings settings, final Path configPath) throws Exception {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Connection>() {
                @Override
                public Connection run() throws Exception {
                    boolean isJava9OrHigher = PlatformDependent.javaVersion() >= 9;
                    ClassLoader originalClassloader = null;
                    if (isJava9OrHigher) {
                        originalClassloader = Thread.currentThread().getContextClassLoader();
                        Thread.currentThread().setContextClassLoader(new Java9CL());
                    }

                    return getConnection0(settings, configPath, originalClassloader, isJava9OrHigher);
                }
            });
        } catch (PrivilegedActionException e) {
            throw e.getException();
        }

    }

    private static List<Map.Entry<String, Settings>> getRoleSearchSettings(Settings settings) {
        Map<String, Settings> groupedSettings = settings.getGroups(ConfigConstants.LDAP_AUTHZ_ROLES, true);

        if (!groupedSettings.isEmpty()) {
            // New style settings
            return Utils.getOrderedBaseSettings(groupedSettings);
        } else {
            // Old style settings
            return convertOldStyleSettingsToNewStyle(settings);
        }
    }

    private static List<Map.Entry<String, Settings>> convertOldStyleSettingsToNewStyle(Settings settings) {
        Map<String, Settings> result = new HashMap<>(1);

        Settings.Builder settingsBuilder = Settings.builder();

        settingsBuilder.put(ConfigConstants.LDAP_AUTHCZ_BASE,
                settings.get(ConfigConstants.LDAP_AUTHZ_ROLEBASE, DEFAULT_ROLEBASE));
        settingsBuilder.put(ConfigConstants.LDAP_AUTHCZ_SEARCH,
                settings.get(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, DEFAULT_ROLESEARCH));

        result.put("convertedOldStyleSettings", settingsBuilder.build());

        return Collections.singletonList(result.entrySet().iterator().next());
    }

    @SuppressWarnings("unchecked")
    private static void checkConnection0(final ConnectionConfig connectionConfig, String bindDn, byte[] password, final ClassLoader cl,
                                         final boolean needRestore) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
                                         FileNotFoundException, IOException, LdapException {

        Connection connection = null;

        try {

            if (log.isDebugEnabled()) {
                log.debug("bindDn {}, password {}", bindDn, password != null && password.length > 0 ? "****" : "<not set>");
            }

            if (bindDn != null && (password == null || password.length == 0)) {
                throw new LdapException("no bindDn or no Password");
            }

            ConnectionConfig config = ConnectionConfig.newConnectionConfig(connectionConfig);
            config.setConnectionInitializer(new BindConnectionInitializer(bindDn, new Credential(password)));

            DefaultConnectionFactory connFactory = new DefaultConnectionFactory(config);
            connection = connFactory.getConnection();

            connection.open();
        } finally {
            Utils.unbindAndCloseSilently(connection);
            connection = null;
            if (needRestore) {
                try {
                    AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                        @Override
                        public Void run() throws Exception {
                            Thread.currentThread().setContextClassLoader(cl);
                            return null;
                        }
                    });
                } catch (PrivilegedActionException e) {
                    log.warn("Unable to restore classloader because of ", e);
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Connection getConnection0(final Settings settings, final Path configPath, final ClassLoader cl,
            final boolean needRestore) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            FileNotFoundException, IOException, LdapException {
        final boolean enableSSL = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL, false);

        final List<String> ldapHosts = settings.getAsList(ConfigConstants.LDAP_HOSTS,
                Collections.singletonList("localhost"));

        Connection connection = null;
        Exception lastException = null;

        final boolean isDebugEnabled = log.isDebugEnabled();
        final boolean isTraceEnabled = log.isTraceEnabled();
        for (String ldapHost : ldapHosts) {

            if (isTraceEnabled) {
                log.trace("Connect to {}", ldapHost);
            }

            try {

                final String[] split = ldapHost.split(":");

                int port;

                if (split.length > 1) {
                    port = Integer.parseInt(split[1]);
                } else {
                    port = enableSSL ? 636 : 389;
                }

                final ConnectionConfig config = new ConnectionConfig();
                config.setLdapUrl("ldap" + (enableSSL ? "s" : "") + "://" + split[0] + ":" + port);

                if (isTraceEnabled) {
                    log.trace("Connect to {}", config.getLdapUrl());
                }

                configureSSL(config, settings, configPath);

                final String bindDn = settings.get(ConfigConstants.LDAP_BIND_DN, null);
                final String password = settings.get(ConfigConstants.LDAP_PASSWORD, null);

                if (isDebugEnabled) {
                    log.debug("bindDn {}, password {}", bindDn,
                            password != null && password.length() > 0 ? "****" : "<not set>");
                }

                if (bindDn != null && (password == null || password.length() == 0)) {
                    log.error("No password given for bind_dn {}. Will try to authenticate anonymously to ldap", bindDn);
                }

                final boolean enableClientAuth = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH,
                        ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH_DEFAULT);

                if (isDebugEnabled) {
                    if (enableClientAuth && bindDn == null) {
                        log.debug("Will perform External SASL bind because client cert authentication is enabled");
                    } else if (bindDn == null) {
                        log.debug("Will perform anonymous bind because no bind dn is given");
                    } else if (enableClientAuth && bindDn != null) {
                        log.debug(
                                "Will perform simple bind with bind dn because to bind dn is given and overrides client cert authentication");
                    } else if (!enableClientAuth && bindDn != null) {
                        log.debug("Will perform simple bind with bind dn");
                    }
                }

                if (bindDn != null && password != null && password.length() > 0) {
                    config.setConnectionInitializer(new BindConnectionInitializer(bindDn, new Credential(password)));
                } else if (enableClientAuth) {
                    SaslConfig saslConfig = new SaslConfig();
                    saslConfig.setMechanism(Mechanism.EXTERNAL);
                    BindConnectionInitializer bindConnectionInitializer = new BindConnectionInitializer();
                    bindConnectionInitializer.setBindSaslConfig(saslConfig);
                    config.setConnectionInitializer(bindConnectionInitializer);
                } else {
                    // No authentication
                }

                DefaultConnectionFactory connFactory = new DefaultConnectionFactory(config);
                connection = connFactory.getConnection();

                connection.open();

                if (connection != null && connection.isOpen()) {
                    break;
                } else {
                    Utils.unbindAndCloseSilently(connection);
                    if (needRestore) {
                        restoreClassLoader0(cl);
                    }
                    connection = null;
                }
            } catch (final Exception e) {
                lastException = e;
                log.warn("Unable to connect to ldapserver {} due to {}. Try next.", ldapHost, e.toString());
                Utils.unbindAndCloseSilently(connection);
                if (needRestore) {
                    restoreClassLoader0(cl);
                }
                connection = null;
                continue;
            }
        }

        if (connection == null || !connection.isOpen()) {
            Utils.unbindAndCloseSilently(connection);  //just in case
            if (needRestore) {
                restoreClassLoader0(cl);
            }
            connection = null;
            if (lastException == null) {
                throw new LdapException("Unable to connect to any of those ldap servers " + ldapHosts);
            } else {
                throw new LdapException(
                        "Unable to connect to any of those ldap servers " + ldapHosts + " due to " + lastException,
                        lastException);
            }
        }

        final Connection delegate = connection;

        if (isDebugEnabled) {
            log.debug("Opened a connection, total count is now {}", CONNECTION_COUNTER.incrementAndGet());
        }

        return new Connection() {

            @Override
            public Response<Void> reopen(BindRequest request) throws LdapException {
                if (isDebugEnabled) {
                    log.debug("Reopened a connection");
                }
                return delegate.reopen(request);
            }

            @Override
            public Response<Void> reopen() throws LdapException {
                if (isDebugEnabled) {
                    log.debug("Reopened a connection");
                }
                return delegate.reopen();
            }

            @Override
            public Response<Void> open(BindRequest request) throws LdapException {
                
                try {
                    if(isDebugEnabled && delegate != null && delegate.isOpen()) {
                        log.debug("Opened a connection, total count is now {}", CONNECTION_COUNTER.incrementAndGet());
                    }
                } catch (Throwable e) {
                    //ignore
                }
                
                return delegate.open(request);
            }

            @Override
            public Response<Void> open() throws LdapException {
                
                try {
                    if(isDebugEnabled && delegate != null && delegate.isOpen()) {
                        log.debug("Opened a connection, total count is now {}", CONNECTION_COUNTER.incrementAndGet());
                    }
                } catch (Throwable e) {
                    //ignore
                }
                
                return delegate.open();
            }

            @Override
            public boolean isOpen() {
                return delegate.isOpen();
            }

            @Override
            public ProviderConnection getProviderConnection() {
                return delegate.getProviderConnection();
            }

            @Override
            public ConnectionConfig getConnectionConfig() {
                return delegate.getConnectionConfig();
            }

            @Override
            public void close(RequestControl[] controls) {
                
                try {
                    if(isDebugEnabled && delegate != null && delegate.isOpen()) {
                        log.debug("Closed a connection, total count is now {}", CONNECTION_COUNTER.decrementAndGet());
                    }
                } catch (Throwable e) {
                    //ignore
                }
                
                try {
                    delegate.close(controls);
                } finally {
                    restoreClassLoader();
                }
            }

            @Override
            public void close() {
                
                try {
                    if(isDebugEnabled && delegate != null && delegate.isOpen()) {
                        log.debug("Closed a connection, total count is now {}", CONNECTION_COUNTER.decrementAndGet());
                    }
                } catch (Throwable e) {
                    //ignore
                }
                
                try {
                    delegate.close();
                } finally {
                    restoreClassLoader();
                }
            }

            private void restoreClassLoader() {
                if (needRestore) {
                    restoreClassLoader0(cl);
                }
            }
        };
    }

    private static void restoreClassLoader0(final ClassLoader cl) {
        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                @Override
                public Void run() throws Exception {
                    Thread.currentThread().setContextClassLoader(cl);
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            log.warn("Unable to restore classloader because of", e);
        }
    }

    private static void configureSSL(final ConnectionConfig config, final Settings settings,
            final Path configPath) throws Exception {

        final boolean isDebugEnabled = log.isDebugEnabled();
        final boolean enableSSL = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL, false);
        final boolean enableStartTLS = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_START_TLS, false);

        if (enableSSL || enableStartTLS) {

            final boolean enableClientAuth = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH,
                    ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH_DEFAULT);

            final boolean trustAll = settings.getAsBoolean(ConfigConstants.LDAPS_TRUST_ALL, false);

            final boolean verifyHostnames = !trustAll && settings.getAsBoolean(ConfigConstants.LDAPS_VERIFY_HOSTNAMES,
                    ConfigConstants.LDAPS_VERIFY_HOSTNAMES_DEFAULT);

            if (isDebugEnabled) {
                log.debug("verifyHostname {}:", verifyHostnames);
                log.debug("trustall {}:", trustAll);
            }

            if (enableStartTLS && !verifyHostnames) {
                System.setProperty("jndi.starttls.allowAnyHostname", "true");
            }

            final boolean pem = settings.get(ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH, null) != null
                    || settings.get(ConfigConstants.LDAPS_PEMTRUSTEDCAS_CONTENT, null) != null;

            final SslConfig sslConfig = new SslConfig();
            CredentialConfig cc;

            if (pem) {
                X509Certificate[] trustCertificates = PemKeyReader.loadCertificatesFromStream(
                        PemKeyReader.resolveStream(ConfigConstants.LDAPS_PEMTRUSTEDCAS_CONTENT, settings));

                if (trustCertificates == null) {
                    trustCertificates = PemKeyReader.loadCertificatesFromFile(PemKeyReader
                            .resolve(ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH, settings, configPath, !trustAll));
                }
                // for client authentication
                X509Certificate authenticationCertificate = PemKeyReader.loadCertificateFromStream(
                        PemKeyReader.resolveStream(ConfigConstants.LDAPS_PEMCERT_CONTENT, settings));

                if (authenticationCertificate == null) {
                    authenticationCertificate = PemKeyReader.loadCertificateFromFile(PemKeyReader
                            .resolve(ConfigConstants.LDAPS_PEMCERT_FILEPATH, settings, configPath, enableClientAuth));
                }

                PrivateKey authenticationKey = PemKeyReader.loadKeyFromStream(
                        settings.get(ConfigConstants.LDAPS_PEMKEY_PASSWORD),
                        PemKeyReader.resolveStream(ConfigConstants.LDAPS_PEMKEY_CONTENT, settings));

                if (authenticationKey == null) {
                    authenticationKey = PemKeyReader
                            .loadKeyFromFile(settings.get(ConfigConstants.LDAPS_PEMKEY_PASSWORD), PemKeyReader.resolve(
                                    ConfigConstants.LDAPS_PEMKEY_FILEPATH, settings, configPath, enableClientAuth));
                }

                cc = CredentialConfigFactory.createX509CredentialConfig(trustCertificates, authenticationCertificate,
                        authenticationKey);

                if (isDebugEnabled) {
                    log.debug("Use PEM to secure communication with LDAP server (client auth is {})",
                            authenticationKey != null);
                }

            } else {
                final KeyStore trustStore = PemKeyReader.loadKeyStore(
                        PemKeyReader.resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, settings,
                                configPath, !trustAll),
                        settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD,
                                SSLConfigConstants.DEFAULT_STORE_PASSWORD),
                        settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE));

                final List<String> trustStoreAliases = settings.getAsList(ConfigConstants.LDAPS_JKS_TRUST_ALIAS, null);

                // for client authentication
                final KeyStore keyStore = PemKeyReader.loadKeyStore(
                        PemKeyReader.resolve(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, settings,
                                configPath, enableClientAuth),
                        settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD,
                                SSLConfigConstants.DEFAULT_STORE_PASSWORD),
                        settings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE));
                final String keyStorePassword = settings.get(
                        SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD,
                        SSLConfigConstants.DEFAULT_STORE_PASSWORD);

                final String keyStoreAlias = settings.get(ConfigConstants.LDAPS_JKS_CERT_ALIAS, null);
                final String[] keyStoreAliases = keyStoreAlias == null ? null : new String[] { keyStoreAlias };

                if (enableClientAuth && keyStoreAliases == null) {
                    throw new IllegalArgumentException(ConfigConstants.LDAPS_JKS_CERT_ALIAS + " not given");
                }

                if (isDebugEnabled) {
                    log.debug("Use Trust-/Keystore to secure communication with LDAP server (client auth is {})",
                            keyStore != null);
                    log.debug("trustStoreAliases: {}, keyStoreAlias: {}", trustStoreAliases, keyStoreAlias);
                }

                cc = CredentialConfigFactory.createKeyStoreCredentialConfig(trustStore,
                        trustStoreAliases == null ? null : trustStoreAliases.toArray(new String[0]), keyStore,
                        keyStorePassword, keyStoreAliases);

            }

            sslConfig.setCredentialConfig(cc);

            if (trustAll) {
                sslConfig.setTrustManagers(new AllowAnyTrustManager());
            }

            if (!verifyHostnames) {
                sslConfig.setHostnameVerifier(new AllowAnyHostnameVerifier());
                final String deiProp = System.getProperty(COM_SUN_JNDI_LDAP_OBJECT_DISABLE_ENDPOINT_IDENTIFICATION);

                if (deiProp == null || !Boolean.parseBoolean(deiProp)) {
                    log.warn("In order to disable host name verification for LDAP connections (verify_hostnames: true), "
                            + "you also need to set set the system property "+COM_SUN_JNDI_LDAP_OBJECT_DISABLE_ENDPOINT_IDENTIFICATION+" to true when starting the JVM running OpenSearch. "
                            + "This applies for all Java versions released since July 2018.");
                    // See:
                    // https://www.oracle.com/technetwork/java/javase/8u181-relnotes-4479407.html
                    // https://www.oracle.com/technetwork/java/javase/10-0-2-relnotes-4477557.html
                    // https://www.oracle.com/technetwork/java/javase/11-0-1-relnotes-5032023.html
                }

                System.setProperty(COM_SUN_JNDI_LDAP_OBJECT_DISABLE_ENDPOINT_IDENTIFICATION, "true");

            }

            final List<String> enabledCipherSuites = settings.getAsList(ConfigConstants.LDAPS_ENABLED_SSL_CIPHERS,
                    Collections.emptyList());
            final List<String> enabledProtocols = settings.getAsList(ConfigConstants.LDAPS_ENABLED_SSL_PROTOCOLS,
                    DEFAULT_TLS_PROTOCOLS);

            if (!enabledCipherSuites.isEmpty()) {
                sslConfig.setEnabledCipherSuites(enabledCipherSuites.toArray(new String[0]));
                log.debug("enabled ssl cipher suites for ldaps {}", enabledCipherSuites);
            }

            log.debug("enabled ssl/tls protocols for ldaps {}", enabledProtocols);
            sslConfig.setEnabledProtocols(enabledProtocols.toArray(new String[0]));
            config.setSslConfig(sslConfig);
        }

        config.setUseSSL(enableSSL);
        config.setUseStartTLS(enableStartTLS);

        final long connectTimeout = settings.getAsLong(ConfigConstants.LDAP_CONNECT_TIMEOUT, 5000L); // 0L means TCP
                                                                                                     // default timeout
        final long responseTimeout = settings.getAsLong(ConfigConstants.LDAP_RESPONSE_TIMEOUT, 0L); // 0L means wait
                                                                                                    // infinitely

        config.setConnectTimeout(Duration.ofMillis(connectTimeout < 0L ? 0L : connectTimeout)); // 5 sec by default
        config.setResponseTimeout(Duration.ofMillis(responseTimeout < 0L ? 0L : responseTimeout));

        if (isDebugEnabled) {
            log.debug("Connect timeout: " + config.getConnectTimeout() + "/ResponseTimeout: "
                    + config.getResponseTimeout());
        }
    }

    @Override
    public void fillRoles(final User user, final AuthCredentials optionalAuthCreds)
            throws OpenSearchSecurityException {

        if (user == null) {
            return;
        }

        String authenticatedUser;
        String originalUserName;
        LdapEntry entry = null;
        String dn = null;

        final boolean isDebugEnabled = log.isDebugEnabled();
        if (isDebugEnabled){
            log.debug("DBGTRACE (2): username: {} -> {}", user.getName(), Arrays.toString(user.getName().getBytes(StandardCharsets.UTF_8)));
        }

        if (user instanceof LdapUser) {
            entry = ((LdapUser) user).getUserEntry();
            authenticatedUser = entry.getDn();
            originalUserName = ((LdapUser) user).getOriginalUsername();
        } else {
            authenticatedUser = user.getName();
            originalUserName = user.getName();
        }

        if (isDebugEnabled){
            log.debug("DBGTRACE (3): authenticatedUser: {} -> {}", authenticatedUser, Arrays.toString(authenticatedUser.getBytes(StandardCharsets.UTF_8)));
        }


        final boolean rolesearchEnabled = settings.getAsBoolean(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true);

        if (isDebugEnabled) {
            log.debug("Try to get roles for {}", authenticatedUser);
        }

        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("user class: {}", user.getClass());
            log.trace("authenticatedUser: {}", authenticatedUser);
            log.trace("originalUserName: {}", originalUserName);
            log.trace("entry: {}", String.valueOf(entry));
            log.trace("dn: {}", dn);
        }

        if (skipUsersMatcher.test(originalUserName) || skipUsersMatcher.test(authenticatedUser)) {
            if (isDebugEnabled) {
                log.debug("Skipped search roles of user {}/{}", authenticatedUser, originalUserName);
            }
            return;
        }

        Connection connection = null;

        try {

            if (entry == null || dn == null) {

                connection = getConnection(settings, configPath);

                if (isValidDn(authenticatedUser)) {
                    // assume dn
                    if (isTraceEnabled) {
                        log.trace("{} is a valid DN", authenticatedUser);
                    }

                    if (isDebugEnabled){
                        log.debug("DBGTRACE (4): authenticatedUser="+authenticatedUser+" -> "+Arrays.toString(authenticatedUser.getBytes(StandardCharsets.UTF_8)));
                    }

                    entry = LdapHelper.lookup(connection, authenticatedUser);

                    if (entry == null) {
                        throw new OpenSearchSecurityException("No user '" + authenticatedUser + "' found");
                    }

                } else {

                    if (isDebugEnabled)
                        log.debug("DBGTRACE (5): authenticatedUser="+user.getName()+" -> "+Arrays.toString(user.getName().getBytes(StandardCharsets.UTF_8)));

                    entry = LDAPAuthenticationBackend.exists(user.getName(), connection, settings, userBaseSettings);

                    if (isTraceEnabled) {
                        log.trace("{} is not a valid DN and was resolved to {}", authenticatedUser, entry);
                    }

                    if (entry == null || entry.getDn() == null) {
                        throw new OpenSearchSecurityException("No user " + authenticatedUser + " found");
                    }
                }

                dn = entry.getDn();

                if (isTraceEnabled) {
                    log.trace("User found with DN {}", dn);
                }

                if (isDebugEnabled){
                    log.debug("DBGTRACE (6): dn"+dn+" -> "+Arrays.toString(dn.getBytes(StandardCharsets.UTF_8)));
                }

            }

            final Set<LdapName> ldapRoles = new HashSet<>(150);
            final Set<String> nonLdapRoles = new HashSet<>(150);
            final HashMultimap<LdapName, Map.Entry<String, Settings>> resultRoleSearchBaseKeys = HashMultimap.create();

            // Roles as an attribute of the user entry
            // default is userrolename: memberOf
            final String userRoleNames = settings.get(ConfigConstants.LDAP_AUTHZ_USERROLENAME, DEFAULT_USERROLENAME);

            if (isTraceEnabled) {
                log.trace("raw userRoleName(s): {}", userRoleNames);
            }

            // we support more than one rolenames, must be separated by a comma
            for (String userRoleName : userRoleNames.split(",")) {
                final String roleName = userRoleName.trim();
                if (entry.getAttribute(roleName) != null) {
                    final Collection<String> userRoles = entry.getAttribute(roleName).getStringValues();
                    for (final String possibleRoleDN : userRoles) {

                        if (isDebugEnabled){
                            log.debug("DBGTRACE (7): possibleRoleDN"+possibleRoleDN);
                        }

                        if (isValidDn(possibleRoleDN)) {
                            LdapName ldapName = new LdapName(possibleRoleDN);
                            ldapRoles.add(ldapName);
                            resultRoleSearchBaseKeys.putAll(ldapName, this.roleBaseSettings);
                        } else {
                            nonLdapRoles.add(possibleRoleDN);
                        }
                    }
                }
            }

            if (isTraceEnabled) {
                log.trace("User attr. ldap roles count: {}", ldapRoles.size());
                log.trace("User attr. ldap roles {}", ldapRoles);
                log.trace("User attr. non-ldap roles count: {}", nonLdapRoles.size());
                log.trace("User attr. non-ldap roles {}", nonLdapRoles);

            }

            // The attribute in a role entry containing the name of that role, Default is
            // "name".
            // Can also be "dn" to use the full DN as rolename.
            // rolename: name
            final String roleName = settings.get(ConfigConstants.LDAP_AUTHZ_ROLENAME, DEFAULT_ROLENAME);

            if (isTraceEnabled) {
                log.trace("roleName: {}", roleName);
            }

            // Specify the name of the attribute which value should be substituted with {2}
            // Substituted with an attribute value from user's directory entry, of the
            // authenticated user
            // userroleattribute: null
            final String userRoleAttributeName = settings.get(ConfigConstants.LDAP_AUTHZ_USERROLEATTRIBUTE, null);

            if (isTraceEnabled) {
                log.trace("userRoleAttribute: {}", userRoleAttributeName);
                log.trace("rolesearch: {}", settings.get(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, DEFAULT_ROLESEARCH));
            }

            String userRoleAttributeValue = null;
            final LdapAttribute userRoleAttribute = entry.getAttribute(userRoleAttributeName);

            if (userRoleAttribute != null) {
                userRoleAttributeValue = Utils.getSingleStringValue(userRoleAttribute);
            }

            if (rolesearchEnabled) {
                String escapedDn = dn;

                if (isDebugEnabled){
                    log.debug("DBGTRACE (8): escapedDn"+escapedDn);
                }

                for (Map.Entry<String, Settings> roleSearchSettingsEntry : roleBaseSettings) {
                    Settings roleSearchSettings = roleSearchSettingsEntry.getValue();

                    SearchFilter f = new SearchFilter();
                    f.setFilter(roleSearchSettings.get(ConfigConstants.LDAP_AUTHCZ_SEARCH, DEFAULT_ROLESEARCH));
                    f.setParameter(LDAPAuthenticationBackend.ZERO_PLACEHOLDER, escapedDn);
                    f.setParameter(ONE_PLACEHOLDER, originalUserName);
                    f.setParameter(TWO_PLACEHOLDER,
                            userRoleAttributeValue == null ? TWO_PLACEHOLDER : userRoleAttributeValue);

                    List<LdapEntry> rolesResult = LdapHelper.search(connection,
                            roleSearchSettings.get(ConfigConstants.LDAP_AUTHCZ_BASE, DEFAULT_ROLEBASE),
                            f,
                            SearchScope.SUBTREE);

                    if (isTraceEnabled) {
                        log.trace("Results for LDAP group search for {} in base {}:\n{}", escapedDn, roleSearchSettingsEntry.getKey(), rolesResult);
                    }

                    if (rolesResult != null && !rolesResult.isEmpty()) {
                        for (final Iterator<LdapEntry> iterator = rolesResult.iterator(); iterator.hasNext();) {
                            LdapEntry searchResultEntry = iterator.next();
                            LdapName ldapName = new LdapName(searchResultEntry.getDn());
                            ldapRoles.add(ldapName);
                            resultRoleSearchBaseKeys.put(ldapName, roleSearchSettingsEntry);
                        }
                    }
                }
            }

            if (isTraceEnabled) {
                log.trace("roles count total {}", ldapRoles.size());
            }

            // nested roles, makes only sense for DN style role names
            if (nestedRoleMatcher != null) {

                if (isTraceEnabled) {
                    log.trace("Evaluate nested roles");
                }

                final Set<LdapName> nestedReturn = new HashSet<>(ldapRoles);

                for (final LdapName roleLdapName : ldapRoles) {
                    Set<Map.Entry<String, Settings>> nameRoleSearchBaseKeys = resultRoleSearchBaseKeys
                            .get(roleLdapName);

                    if (nameRoleSearchBaseKeys == null) {
                        log.error("Could not find roleSearchBaseKeys for " + roleLdapName + "; existing: "
                                + resultRoleSearchBaseKeys);
                        continue;
                    }

                    final Set<LdapName> nestedRoles = resolveNestedRoles(roleLdapName, connection, userRoleNames, 0,
                            rolesearchEnabled, nameRoleSearchBaseKeys);

                    if (isTraceEnabled) {
                        log.trace("{} nested roles for {}", nestedRoles.size(), roleLdapName);
                    }

                    nestedReturn.addAll(nestedRoles);
                }

                for (final LdapName roleLdapName : nestedReturn) {
                    final String role = getRoleFromEntry(connection, roleLdapName, roleName);

                    if (!Strings.isNullOrEmpty(role)) {
                        user.addRole(role);
                    } else {
                        log.warn("No or empty attribute '{}' for entry {}", roleName, roleLdapName);
                    }
                }

            } else {
                // DN roles, extract rolename according to config
                for (final LdapName roleLdapName : ldapRoles) {
                    final String role = getRoleFromEntry(connection, roleLdapName, roleName);

                    if (!Strings.isNullOrEmpty(role)) {
                        user.addRole(role);
                    } else {
                        log.warn("No or empty attribute '{}' for entry {}", roleName, roleLdapName);
                    }
                }

            }

            // add all non-LDAP roles from user attributes to the final set of backend roles
            for (String nonLdapRoleName : nonLdapRoles) {
                user.addRole(nonLdapRoleName);
            }

            if (isDebugEnabled) {
                log.debug("Roles for {} -> {}", user.getName(), user.getRoles());
            }

            if (isTraceEnabled) {
                log.trace("returned user: {}", user);
            }

        } catch (final Exception e) {
            if (isDebugEnabled) {
                log.debug("Unable to fill user roles due to ", e);
            }
            throw new OpenSearchSecurityException(e.toString(), e);
        } finally {
            Utils.unbindAndCloseSilently(connection);
        }

    }

    protected Set<LdapName> resolveNestedRoles(final LdapName roleDn, final Connection ldapConnection,
            String userRoleName, int depth, final boolean rolesearchEnabled,
            Set<Map.Entry<String, Settings>> roleSearchBaseSettingsSet)
            throws OpenSearchSecurityException, LdapException {

        if (nestedRoleMatcher.test(roleDn.toString())) {

            if (log.isTraceEnabled()) {
                log.trace("Filter nested role {}", roleDn);
            }

            return Collections.emptySet();
        }

        depth++;

        final boolean isDebugEnabled = log.isDebugEnabled();
        final Set<LdapName> result = new HashSet<>(20);
        final HashMultimap<LdapName, Map.Entry<String, Settings>> resultRoleSearchBaseKeys = HashMultimap.create();

        final LdapEntry e0 = LdapHelper.lookup(ldapConnection, roleDn.toString());

        if (e0.getAttribute(userRoleName) != null) {
            final Collection<String> userRoles = e0.getAttribute(userRoleName).getStringValues();

            for (final String possibleRoleDN : userRoles) {

                if (isDebugEnabled){
                    log.debug("DBGTRACE (10): possibleRoleDN"+possibleRoleDN);
                }

                if (isValidDn(possibleRoleDN)) {
                    try {
                        LdapName ldapName = new LdapName(possibleRoleDN);
                        result.add(ldapName);
                        resultRoleSearchBaseKeys.putAll(ldapName, this.roleBaseSettings);
                    } catch (InvalidNameException e) {
                        // ignore
                    }
                } else {
                    if (isDebugEnabled) {
                        log.debug("Cannot add {} as a role because its not a valid dn", possibleRoleDN);
                    }
                }
            }
        }

        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("result nested attr count for depth {} : {}", depth, result.size());
        }

        if (rolesearchEnabled) {
            String escapedDn = roleDn.toString();

            if (isDebugEnabled){
                log.debug("DBGTRACE (10): escapedDn {}", escapedDn);
            }


            for (Map.Entry<String, Settings> roleSearchBaseSettingsEntry : Utils
                    .getOrderedBaseSettings(roleSearchBaseSettingsSet)) {
                Settings roleSearchSettings = roleSearchBaseSettingsEntry.getValue();

                SearchFilter f = new SearchFilter();
                f.setFilter(roleSearchSettings.get(ConfigConstants.LDAP_AUTHCZ_SEARCH, DEFAULT_ROLESEARCH));
                f.setParameter(LDAPAuthenticationBackend.ZERO_PLACEHOLDER, escapedDn);
                f.setParameter(ONE_PLACEHOLDER, escapedDn);

                List<LdapEntry> foundEntries = LdapHelper.search(ldapConnection,
                        roleSearchSettings.get(ConfigConstants.LDAP_AUTHCZ_BASE, DEFAULT_ROLEBASE),
                        f,
                        SearchScope.SUBTREE);

                if (isTraceEnabled) {
                    log.trace("Results for LDAP group search for {} in base {}:\n{}", escapedDn, roleSearchBaseSettingsEntry.getKey(), foundEntries);
                }

                if (foundEntries != null) {
                    for (final LdapEntry entry : foundEntries) {
                        try {
                            final LdapName dn = new LdapName(entry.getDn());
                            result.add(dn);
                            resultRoleSearchBaseKeys.put(dn, roleSearchBaseSettingsEntry);
                        } catch (final InvalidNameException e) {
                            throw new LdapException(e);
                        }
                    }
                }
            }
        }

        int maxDepth = ConfigConstants.LDAP_AUTHZ_MAX_NESTED_DEPTH_DEFAULT;
        try {
            maxDepth = settings.getAsInt(ConfigConstants.LDAP_AUTHZ_MAX_NESTED_DEPTH,
                    ConfigConstants.LDAP_AUTHZ_MAX_NESTED_DEPTH_DEFAULT);
        } catch (Exception e) {
            log.error(ConfigConstants.LDAP_AUTHZ_MAX_NESTED_DEPTH + " is not parseable: " + e, e);
        }

        if (depth < maxDepth) {
            for (final LdapName nm : new HashSet<LdapName>(result)) {
                Set<Map.Entry<String, Settings>> nameRoleSearchBaseKeys = resultRoleSearchBaseKeys.get(nm);

                if (nameRoleSearchBaseKeys == null) {
                    log.error(
                            "Could not find roleSearchBaseKeys for " + nm + "; existing: " + resultRoleSearchBaseKeys);
                    continue;
                }

                final Set<LdapName> in = resolveNestedRoles(nm, ldapConnection, userRoleName, depth, rolesearchEnabled,
                        nameRoleSearchBaseKeys);
                result.addAll(in);
            }
        }

        return result;
    }

    @Override
    public String getType() {
        return "ldap";
    }

    private boolean isValidDn(final String dn) {

        if (Strings.isNullOrEmpty(dn)) {
            return false;
        }

        try {
            new LdapName(dn);
        } catch (final Exception e) {
            return false;
        }

        return true;
    }

    private String getRoleFromEntry(final Connection ldapConnection, final LdapName ldapName, final String role) {

        if (ldapName == null || Strings.isNullOrEmpty(role)) {
            return null;
        }

        if("dn".equalsIgnoreCase(role)) {
            return ldapName.toString();
        }

        try {
            final LdapEntry roleEntry = LdapHelper.lookup(ldapConnection, ldapName.toString());

            if(roleEntry != null) {
                final LdapAttribute roleAttribute = roleEntry.getAttribute(role);
                if(roleAttribute != null) {
                    return Utils.getSingleStringValue(roleAttribute);
                }
            }
        } catch (LdapException e) {
            log.error("Unable to handle role {} because of ", ldapName, e);
        }

        return null;
    }

    @SuppressWarnings("rawtypes")
    private final static Class clazz = ThreadLocalTLSSocketFactory.class;

    private final static class Java9CL extends ClassLoader {

        public Java9CL() {
            super();
        }

        @SuppressWarnings("unused")
        public Java9CL(ClassLoader parent) {
            super(parent);
        }

        @SuppressWarnings({ "rawtypes", "unchecked" })
        @Override
        public Class loadClass(String name) throws ClassNotFoundException {

            if (!name.equalsIgnoreCase("org.ldaptive.ssl.ThreadLocalTLSSocketFactory")) {
                return super.loadClass(name);
            }

            return clazz;
        }

    }
}
