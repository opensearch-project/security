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

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.Destroyable;
import org.opensearch.security.auth.ImpersonationBackend;
import org.opensearch.security.auth.ldap.backend.LDAPAuthenticationBackend;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.auth.ldap.util.Utils;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.security.util.SettingsBasedSSLConfigurator.SSLConfigException;

import org.ldaptive.BindRequest;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.Credential;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.pool.ConnectionPool;

public class LDAPAuthenticationBackend2 implements AuthenticationBackend, ImpersonationBackend, Destroyable {

    protected static final Logger log = LogManager.getLogger(LDAPAuthenticationBackend2.class);

    private final Settings settings;

    private ConnectionPool connectionPool;
    private ConnectionFactory connectionFactory;
    private ConnectionFactory authConnectionFactory;
    private LDAPUserSearcher userSearcher;
    private final int customAttrMaxValueLen;
    private final WildcardMatcher allowlistedCustomLdapAttrMatcher;
    private final String[] returnAttributes;
    private final boolean shouldFollowReferrals;

    public LDAPAuthenticationBackend2(final Settings settings, final Path configPath) throws SSLConfigException {
        this.settings = settings;

        LDAPConnectionFactoryFactory ldapConnectionFactoryFactory = new LDAPConnectionFactoryFactory(settings, configPath);

        this.connectionPool = ldapConnectionFactoryFactory.createConnectionPool();
        this.connectionFactory = ldapConnectionFactoryFactory.createConnectionFactory(this.connectionPool);

        if (this.connectionPool != null) {
            this.authConnectionFactory = ldapConnectionFactoryFactory.createBasicConnectionFactory();
        } else {
            this.authConnectionFactory = this.connectionFactory;
        }

        this.userSearcher = new LDAPUserSearcher(settings);
        this.returnAttributes = settings.getAsList(ConfigConstants.LDAP_RETURN_ATTRIBUTES, Arrays.asList(ReturnAttributes.ALL.value()))
            .toArray(new String[0]);
        this.shouldFollowReferrals = settings.getAsBoolean(ConfigConstants.FOLLOW_REFERRALS, ConfigConstants.FOLLOW_REFERRALS_DEFAULT);
        customAttrMaxValueLen = settings.getAsInt(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 36);
        allowlistedCustomLdapAttrMatcher = WildcardMatcher.from(
            settings.getAsList(ConfigConstants.LDAP_CUSTOM_ATTR_WHITELIST, Collections.singletonList("*"))
        );
    }

    @Override
    public User authenticate(AuthenticationContext context) throws OpenSearchSecurityException {
        try {
            return AccessController.doPrivilegedChecked(() -> authenticate0(context));
        } catch (Exception e) {
            if (e instanceof OpenSearchSecurityException) {
                throw (OpenSearchSecurityException) e;
            } else if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private User authenticate0(AuthenticationContext context) throws OpenSearchSecurityException {

        Connection ldapConnection = null;
        final String user = context.getCredentials().getUsername();
        byte[] password = context.getCredentials().getPassword();

        try {

            ldapConnection = connectionFactory.getConnection();
            ldapConnection.open();

            LdapEntry entry = userSearcher.exists(ldapConnection, user, this.returnAttributes, this.shouldFollowReferrals);

            // fake a user that no exists
            // makes guessing if a user exists or not harder when looking on the
            // authentication delay time
            if (entry == null && settings.getAsBoolean(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, false)) {
                String fakeLognDn = settings.get(
                    ConfigConstants.LDAP_FAKE_LOGIN_DN,
                    "CN=faketomakebindfail,DC=" + UUID.randomUUID().toString()
                );
                entry = new LdapEntry(fakeLognDn);
                password = settings.get(ConfigConstants.LDAP_FAKE_LOGIN_PASSWORD, "fakeLoginPwd123").getBytes(StandardCharsets.UTF_8);
            } else if (entry == null) {
                throw new OpenSearchSecurityException("No user " + user + " found");
            }

            final String dn = entry.getDn();

            if (log.isTraceEnabled()) {
                log.trace("Try to authenticate dn {}", dn);
            }

            if (this.connectionPool == null) {
                authenticateByLdapServer(ldapConnection, dn, password);
            } else {
                authenticateByLdapServerWithSeparateConnection(dn, password);
            }

            final String usernameAttribute = settings.get(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, null);
            String username = dn;

            if (usernameAttribute != null && entry.getAttribute(usernameAttribute) != null) {
                username = Utils.getSingleStringValue(entry.getAttribute(usernameAttribute));
            }

            if (log.isDebugEnabled()) {
                log.debug("Authenticated username {}", username);
            }

            // Make LdapEntry available to authz backends by adding it to the AuthencationContext
            context.addContextData(LdapEntry.class, entry);

            // by default all ldap attributes which are not binary and with a max value
            // length of 36 are included in the user object
            // if the whitelist contains at least one value then all attributes will be
            // additional check if whitelisted (whitelist can contain wildcard and regex)
            ImmutableMap<String, String> userAttributes = LDAPAuthenticationBackend.extractLdapAttributes(
                user,
                entry,
                customAttrMaxValueLen,
                allowlistedCustomLdapAttrMatcher
            );
            return new User(username, ImmutableSet.of(), ImmutableSet.of(), null, userAttributes, false);
        } catch (final Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to authenticate user due to ", e);
            }
            throw new OpenSearchSecurityException(e.toString(), e);
        } finally {
            Arrays.fill(password, (byte) '\0');
            password = null;
            Utils.unbindAndCloseSilently(ldapConnection);
        }

    }

    @Override
    public String getType() {
        return "ldap";
    }

    @Override
    public Optional<User> impersonate(User user) {
        return AccessController.doPrivileged(() -> {
            Connection ldapConnection = null;
            String userName = user.getName();

            try {
                ldapConnection = this.connectionFactory.getConnection();
                ldapConnection.open();
                LdapEntry userEntry = this.userSearcher.exists(ldapConnection, userName, this.returnAttributes, this.shouldFollowReferrals);

                if (userEntry != null) {
                    return Optional.of(
                        user.withAttributes(
                            LDAPAuthenticationBackend.extractLdapAttributes(
                                userName,
                                userEntry,
                                customAttrMaxValueLen,
                                allowlistedCustomLdapAttrMatcher
                            )
                        )
                    );
                } else {
                    return Optional.empty();
                }
            } catch (final Exception e) {
                log.warn("User {} does not exist due to exception", userName, e);
                return Optional.empty();
            } finally {
                Utils.unbindAndCloseSilently(ldapConnection);
            }
        });
    }

    private void authenticateByLdapServer(final Connection connection, final String dn, byte[] password) throws LdapException {
        try {
            AccessController.doPrivilegedChecked(
                () -> connection.getProviderConnection().bind(new BindRequest(dn, new Credential(password)))
            );
        } catch (Exception e) {
            if (e instanceof LdapException) {
                throw (LdapException) e;
            } else if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private void authenticateByLdapServerWithSeparateConnection(final String dn, byte[] password) throws LdapException {
        try (Connection unpooledConnection = this.authConnectionFactory.getConnection()) {
            unpooledConnection.open();
            authenticateByLdapServer(unpooledConnection, dn, password);
        }
    }

    @Override
    public void destroy() {
        if (this.connectionPool != null) {
            this.connectionPool.close();
            this.connectionPool = null;
        }

    }

}
