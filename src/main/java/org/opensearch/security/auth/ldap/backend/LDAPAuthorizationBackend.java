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

package org.opensearch.security.auth.ldap.backend;

import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
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
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import com.google.common.collect.HashMultimap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.Strings;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.AuthorizationBackend;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.auth.ldap.util.LdapHelper;
import org.opensearch.security.auth.ldap.util.Utils;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.PemKeyReader;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

import org.ldaptive.BindConnectionInitializer;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.Credential;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.FilterTemplate;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.SearchScope;
import org.ldaptive.sasl.Mechanism;
import org.ldaptive.sasl.SaslConfig;
import org.ldaptive.ssl.AllowAnyHostnameVerifier;
import org.ldaptive.ssl.AllowAnyTrustManager;
import org.ldaptive.ssl.CredentialConfig;
import org.ldaptive.ssl.CredentialConfigFactory;
import org.ldaptive.ssl.SslConfig;

import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD;

public class LDAPAuthorizationBackend implements AuthorizationBackend {

    private static final List<String> DEFAULT_TLS_PROTOCOLS = Arrays.asList("TLSv1.2", "TLSv1.3");
    static final int ONE_PLACEHOLDER = 1;
    static final int TWO_PLACEHOLDER = 2;
    static final String DEFAULT_ROLEBASE = "";
    static final String DEFAULT_ROLESEARCH = "(member={0})";
    static final String DEFAULT_ROLENAME = "name";
    static final String DEFAULT_USERROLENAME = "memberOf";

    protected static final Logger log = LogManager.getLogger(LDAPAuthorizationBackend.class);
    private final Settings settings;
    private final WildcardMatcher skipUsersMatcher;
    private final WildcardMatcher excludeRolesMatcher;
    private final WildcardMatcher nestedRoleMatcher;
    private final Path configPath;
    private final List<Map.Entry<String, Settings>> roleBaseSettings;
    private final List<Map.Entry<String, Settings>> userBaseSettings;

    private final String[] returnAttributes;
    private final boolean shouldFollowReferrals;

    public LDAPAuthorizationBackend(final Settings settings, final Path configPath) {
        this.settings = settings;
        this.skipUsersMatcher = WildcardMatcher.from(settings.getAsList(ConfigConstants.LDAP_AUTHZ_SKIP_USERS));
        this.excludeRolesMatcher = WildcardMatcher.from(settings.getAsList(ConfigConstants.LDAP_AUTHZ_EXCLUDE_ROLES));
        this.nestedRoleMatcher = settings.getAsBoolean(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false)
            ? WildcardMatcher.from(settings.getAsList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER))
            : null;
        this.configPath = configPath;
        this.roleBaseSettings = getRoleSearchSettings(settings);
        this.userBaseSettings = LDAPAuthenticationBackend.getUserBaseSettings(settings);
        this.returnAttributes = settings.getAsList(ConfigConstants.LDAP_RETURN_ATTRIBUTES, Arrays.asList(ReturnAttributes.ALL.value()))
            .toArray(new String[0]);
        this.shouldFollowReferrals = settings.getAsBoolean(ConfigConstants.FOLLOW_REFERRALS, ConfigConstants.FOLLOW_REFERRALS_DEFAULT);
    }

    public static void checkConnection(final Settings settings, final Path configPath, String bindDn, byte[] password) throws Exception {
        AccessController.doPrivilegedChecked(() -> {
            if (log.isDebugEnabled()) {
                log.debug("bindDn {}, password {}", bindDn, password != null && password.length > 0 ? "****" : "<not set>");
            }

            if (bindDn != null && (password == null || password.length == 0)) {
                throw new LdapException("no bindDn or no Password");
            }

            ConnectionConfig config = createConnectionConfig(settings, configPath);
            ConnectionConfig.Builder builder = ConnectionConfig.builder()
                .url(config.getLdapUrl())
                .useStartTLS(config.getUseStartTLS())
                .connectTimeout(config.getConnectTimeout())
                .responseTimeout(config.getResponseTimeout())
                .sslConfig(config.getSslConfig())
                .connectionInitializers(BindConnectionInitializer.builder().dn(bindDn).credential(new Credential(password)).build());

            DefaultConnectionFactory connFactory = new DefaultConnectionFactory(builder.build());
            try (var conn = connFactory.getConnection()) {
                conn.open();
            }
            return null;
        });
    }

    public static ConnectionFactory getConnectionFactory(final Settings settings, final Path configPath) throws Exception {
        return AccessController.doPrivilegedChecked(() -> {
            ConnectionConfig config = createConnectionConfig(settings, configPath);
            return new DefaultConnectionFactory(config);
        });
    }

    private static List<Map.Entry<String, Settings>> getRoleSearchSettings(Settings settings) {
        Map<String, Settings> groupedSettings = settings.getGroups(ConfigConstants.LDAP_AUTHZ_ROLES, true);

        if (!groupedSettings.isEmpty()) {
            return Utils.getOrderedBaseSettings(groupedSettings);
        } else {
            return convertOldStyleSettingsToNewStyle(settings);
        }
    }

    private static List<Map.Entry<String, Settings>> convertOldStyleSettingsToNewStyle(Settings settings) {
        Map<String, Settings> result = new HashMap<>(1);
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(ConfigConstants.LDAP_AUTHCZ_BASE, settings.get(ConfigConstants.LDAP_AUTHZ_ROLEBASE, DEFAULT_ROLEBASE));
        settingsBuilder.put(ConfigConstants.LDAP_AUTHCZ_SEARCH, settings.get(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, DEFAULT_ROLESEARCH));
        result.put("convertedOldStyleSettings", settingsBuilder.build());
        return Collections.singletonList(result.entrySet().iterator().next());
    }

    private static ConnectionConfig createConnectionConfig(final Settings settings, final Path configPath) throws Exception {
        final boolean enableSSL = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL, false);
        final List<String> ldapHosts = settings.getAsList(ConfigConstants.LDAP_HOSTS, Collections.singletonList("localhost"));

        StringBuilder urlBuilder = new StringBuilder();
        for (String ldapHost : ldapHosts) {
            if (urlBuilder.length() > 0) urlBuilder.append(" ");
            if (ldapHost.contains("://")) {
                urlBuilder.append(ldapHost);
            } else {
                String[] split = ldapHost.split(":");
                int port = split.length > 1 ? Integer.parseInt(split[1]) : (enableSSL ? 636 : 389);
                urlBuilder.append("ldap").append(enableSSL ? "s" : "").append("://").append(split[0]).append(":").append(port);
            }
        }

        ConnectionConfig.Builder builder = ConnectionConfig.builder().url(urlBuilder.toString());

        configureSSL(builder, settings, configPath);
        configureBindCredentials(builder, settings);

        long connectTimeout = settings.getAsLong(ConfigConstants.LDAP_CONNECT_TIMEOUT, 5000L);
        long responseTimeout = settings.getAsLong(ConfigConstants.LDAP_RESPONSE_TIMEOUT, 0L);
        builder.connectTimeout(Duration.ofMillis(connectTimeout < 0L ? 0L : connectTimeout));
        builder.responseTimeout(Duration.ofMillis(responseTimeout < 0L ? 0L : responseTimeout));

        return builder.build();
    }

    private static void configureBindCredentials(ConnectionConfig.Builder builder, Settings settings) {
        final String bindDn = settings.get(ConfigConstants.LDAP_BIND_DN, null);
        final String password = settings.get(ConfigConstants.LDAP_PASSWORD, null);
        final boolean enableClientAuth = settings.getAsBoolean(
            ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH,
            ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH_DEFAULT
        );

        if (bindDn != null && password != null && !password.isEmpty()) {
            builder.connectionInitializers(BindConnectionInitializer.builder().dn(bindDn).credential(new Credential(password)).build());
        } else if (enableClientAuth) {
            builder.connectionInitializers(
                BindConnectionInitializer.builder().saslConfig(SaslConfig.builder().mechanism(Mechanism.EXTERNAL).build()).build()
            );
        }
    }

    private static void configureSSL(ConnectionConfig.Builder builder, Settings settings, Path configPath) throws Exception {
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

    @Override
    public User addRoles(User user, AuthenticationContext context) throws OpenSearchSecurityException {
        if (user == null) {
            return user;
        }

        String authenticatedUser;
        String originalUserName = context.getCredentials().getUsername();
        LdapEntry entry = context.getContextData(LdapEntry.class).orElse(null);
        String dn;

        if (entry != null) {
            dn = entry.getDn();
            authenticatedUser = dn;
        } else {
            dn = null;
            authenticatedUser = user.getName();
        }

        final boolean rolesearchEnabled = settings.getAsBoolean(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true);

        if (skipUsersMatcher.test(originalUserName) || skipUsersMatcher.test(authenticatedUser)) {
            return user;
        }

        ConnectionFactory connectionFactory = null;

        try {
            Set<String> additionalRoles = new HashSet<>();

            if (dn == null) {
                connectionFactory = getConnectionFactory(settings, configPath);

                if (isValidDn(authenticatedUser)) {
                    entry = LdapHelper.lookup(connectionFactory, authenticatedUser, this.returnAttributes, this.shouldFollowReferrals);
                    if (entry == null) {
                        throw new OpenSearchSecurityException("No user '" + authenticatedUser + "' found");
                    }
                } else {
                    entry = LDAPAuthenticationBackend.exists(
                        user.getName(),
                        connectionFactory,
                        settings,
                        userBaseSettings,
                        this.returnAttributes,
                        this.shouldFollowReferrals
                    );
                    if (entry == null || entry.getDn() == null) {
                        throw new OpenSearchSecurityException("No user " + authenticatedUser + " found");
                    }
                }
                dn = entry.getDn();
            }

            final Set<LdapName> ldapRoles = new HashSet<>(150);
            final Set<String> nonLdapRoles = new HashSet<>(150);
            final HashMultimap<LdapName, Map.Entry<String, Settings>> resultRoleSearchBaseKeys = HashMultimap.create();

            final String userRoleNames = settings.get(ConfigConstants.LDAP_AUTHZ_USERROLENAME, DEFAULT_USERROLENAME);

            for (String userRoleName : userRoleNames.split(",")) {
                final String roleName = userRoleName.trim();
                if (entry.getAttribute(roleName) != null) {
                    final Collection<String> userRoles = entry.getAttribute(roleName).getStringValues();
                    for (final String possibleRoleDN : userRoles) {
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

            final String roleName = settings.get(ConfigConstants.LDAP_AUTHZ_ROLENAME, DEFAULT_ROLENAME);
            final String userRoleAttributeName = settings.get(ConfigConstants.LDAP_AUTHZ_USERROLEATTRIBUTE, null);

            String userRoleAttributeValue = null;
            final LdapAttribute userRoleAttribute = entry.getAttribute(userRoleAttributeName);
            if (userRoleAttribute != null) {
                userRoleAttributeValue = Utils.getSingleStringValue(userRoleAttribute);
            }

            if (rolesearchEnabled) {
                if (connectionFactory == null) {
                    connectionFactory = getConnectionFactory(settings, configPath);
                }

                for (Map.Entry<String, Settings> roleSearchSettingsEntry : roleBaseSettings) {
                    Settings roleSearchSettings = roleSearchSettingsEntry.getValue();

                    FilterTemplate filter = FilterTemplate.builder()
                        .filter(roleSearchSettings.get(ConfigConstants.LDAP_AUTHCZ_SEARCH, DEFAULT_ROLESEARCH))
                        .parameters(
                            dn,
                            originalUserName,
                            userRoleAttributeValue == null ? String.valueOf(TWO_PLACEHOLDER) : userRoleAttributeValue
                        )
                        .build();

                    List<LdapEntry> rolesResult = LdapHelper.search(
                        connectionFactory,
                        roleSearchSettings.get(ConfigConstants.LDAP_AUTHCZ_BASE, DEFAULT_ROLEBASE),
                        filter,
                        SearchScope.SUBTREE,
                        this.returnAttributes,
                        this.shouldFollowReferrals
                    );

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

            if (nestedRoleMatcher != null) {
                final Set<LdapName> nestedReturn = new HashSet<>(ldapRoles);

                for (final LdapName roleLdapName : ldapRoles) {
                    Set<Map.Entry<String, Settings>> nameRoleSearchBaseKeys = resultRoleSearchBaseKeys.get(roleLdapName);
                    if (nameRoleSearchBaseKeys == null) continue;

                    if (connectionFactory == null) {
                        connectionFactory = getConnectionFactory(settings, configPath);
                    }

                    final Set<LdapName> nestedRoles = resolveNestedRoles(
                        roleLdapName,
                        connectionFactory,
                        userRoleNames,
                        0,
                        rolesearchEnabled,
                        nameRoleSearchBaseKeys
                    );
                    nestedReturn.addAll(nestedRoles);
                }

                for (final LdapName roleLdapName : nestedReturn) {
                    final String role = getRoleFromEntry(connectionFactory, roleLdapName, roleName);
                    if (role != null && !excludeRolesMatcher.test(role)) {
                        additionalRoles.add(role);
                    }
                }
            } else {
                for (final LdapName roleLdapName : ldapRoles) {
                    final String role = getRoleFromEntry(connectionFactory, roleLdapName, roleName);
                    if (role != null && !excludeRolesMatcher.test(role)) {
                        additionalRoles.add(role);
                    }
                }
            }

            additionalRoles.addAll(nonLdapRoles);
            return user.withRoles(additionalRoles);

        } catch (final Exception e) {
            throw new OpenSearchSecurityException(e.toString(), e);
        } finally {
            closeConnectionFactory(connectionFactory);
        }
    }

    protected Set<LdapName> resolveNestedRoles(
        final LdapName roleDn,
        final ConnectionFactory connectionFactory,
        String userRoleName,
        int depth,
        final boolean rolesearchEnabled,
        Set<Map.Entry<String, Settings>> roleSearchBaseSettingsSet
    ) throws OpenSearchSecurityException, LdapException {

        if (nestedRoleMatcher.test(roleDn.toString())) {
            return Collections.emptySet();
        }

        depth++;

        final Set<LdapName> result = new HashSet<>(20);
        final HashMultimap<LdapName, Map.Entry<String, Settings>> resultRoleSearchBaseKeys = HashMultimap.create();

        final LdapEntry e0 = LdapHelper.lookup(connectionFactory, roleDn.toString(), this.returnAttributes, this.shouldFollowReferrals);

        if (e0 != null && e0.getAttribute(userRoleName) != null) {
            final Collection<String> userRoles = e0.getAttribute(userRoleName).getStringValues();
            for (final String possibleRoleDN : userRoles) {
                if (isValidDn(possibleRoleDN)) {
                    try {
                        LdapName ldapName = new LdapName(possibleRoleDN);
                        result.add(ldapName);
                        resultRoleSearchBaseKeys.putAll(ldapName, this.roleBaseSettings);
                    } catch (InvalidNameException e) {
                        // ignore
                    }
                }
            }
        }

        if (rolesearchEnabled) {
            for (Map.Entry<String, Settings> roleSearchBaseSettingsEntry : Utils.getOrderedBaseSettings(roleSearchBaseSettingsSet)) {
                Settings roleSearchSettings = roleSearchBaseSettingsEntry.getValue();

                FilterTemplate filter = FilterTemplate.builder()
                    .filter(roleSearchSettings.get(ConfigConstants.LDAP_AUTHCZ_SEARCH, DEFAULT_ROLESEARCH))
                    .parameters(roleDn.toString(), roleDn.toString())
                    .build();

                List<LdapEntry> foundEntries = LdapHelper.search(
                    connectionFactory,
                    roleSearchSettings.get(ConfigConstants.LDAP_AUTHCZ_BASE, DEFAULT_ROLEBASE),
                    filter,
                    SearchScope.SUBTREE,
                    this.returnAttributes,
                    this.shouldFollowReferrals
                );

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
            maxDepth = settings.getAsInt(ConfigConstants.LDAP_AUTHZ_MAX_NESTED_DEPTH, ConfigConstants.LDAP_AUTHZ_MAX_NESTED_DEPTH_DEFAULT);
        } catch (Exception e) {
            log.error(ConfigConstants.LDAP_AUTHZ_MAX_NESTED_DEPTH + " is not parseable: ", e);
        }

        if (depth < maxDepth) {
            for (final LdapName nm : new HashSet<>(result)) {
                Set<Map.Entry<String, Settings>> nameRoleSearchBaseKeys = resultRoleSearchBaseKeys.get(nm);
                if (nameRoleSearchBaseKeys == null) continue;

                final Set<LdapName> in = resolveNestedRoles(
                    nm,
                    connectionFactory,
                    userRoleName,
                    depth,
                    rolesearchEnabled,
                    nameRoleSearchBaseKeys
                );
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

    private String getRoleFromEntry(final ConnectionFactory connectionFactory, final LdapName ldapName, final String role) {
        if (ldapName == null || Strings.isNullOrEmpty(role)) {
            return null;
        }

        if ("dn".equalsIgnoreCase(role)) {
            return ldapName.toString();
        }

        try {
            final LdapEntry roleEntry = LdapHelper.lookup(
                connectionFactory,
                ldapName.toString(),
                this.returnAttributes,
                this.shouldFollowReferrals
            );
            if (roleEntry != null) {
                final LdapAttribute roleAttribute = roleEntry.getAttribute(role);
                if (roleAttribute != null) {
                    return Utils.getSingleStringValue(roleAttribute);
                }
            }
        } catch (LdapException e) {
            log.error("Unable to handle role {} because of ", ldapName, e);
        }
        return null;
    }

    private static void closeConnectionFactory(ConnectionFactory connectionFactory) {
        if (connectionFactory instanceof AutoCloseable) {
            try {
                ((AutoCloseable) connectionFactory).close();
            } catch (Exception e) {
                // ignore
            }
        }
    }
}
