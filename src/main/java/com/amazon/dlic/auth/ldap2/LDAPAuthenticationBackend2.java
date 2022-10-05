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

package com.amazon.dlic.auth.ldap2;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.ldaptive.BindRequest;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.Credential;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.pool.ConnectionPool;

import com.amazon.dlic.auth.ldap.LdapUser;
import com.amazon.dlic.auth.ldap.util.ConfigConstants;
import com.amazon.dlic.auth.ldap.util.Utils;
import com.amazon.dlic.util.SettingsBasedSSLConfigurator.SSLConfigException;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.Destroyable;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

public class LDAPAuthenticationBackend2 implements AuthenticationBackend, Destroyable {

    protected static final Logger log = LogManager.getLogger(LDAPAuthenticationBackend2.class);

    private final Settings settings;

    private ConnectionPool connectionPool;
    private ConnectionFactory connectionFactory;
    private ConnectionFactory authConnectionFactory;
    private LDAPUserSearcher userSearcher;
    private final int customAttrMaxValueLen;
    private final WildcardMatcher whitelistedCustomLdapAttrMatcher;
    private final String[] returnAttributes;
    private final boolean shouldFollowReferrals;

    public LDAPAuthenticationBackend2(final Settings settings, final Path configPath) throws SSLConfigException {
        this.settings = settings;

        LDAPConnectionFactoryFactory ldapConnectionFactoryFactory = new LDAPConnectionFactoryFactory(settings,
                configPath);

        this.connectionPool = ldapConnectionFactoryFactory.createConnectionPool();
        this.connectionFactory = ldapConnectionFactoryFactory.createConnectionFactory(this.connectionPool);

        if (this.connectionPool != null) {
            this.authConnectionFactory = ldapConnectionFactoryFactory.createBasicConnectionFactory();
        } else {
            this.authConnectionFactory = this.connectionFactory;
        }

        this.userSearcher = new LDAPUserSearcher(settings);
        this.returnAttributes = settings.getAsList(ConfigConstants.LDAP_RETURN_ATTRIBUTES, Arrays.asList(ReturnAttributes.ALL.value())).toArray(new String[0]);
        this.shouldFollowReferrals = settings.getAsBoolean(ConfigConstants.FOLLOW_REFERRALS, ConfigConstants.FOLLOW_REFERRALS_DEFAULT);
        customAttrMaxValueLen = settings.getAsInt(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 36);
        whitelistedCustomLdapAttrMatcher = WildcardMatcher.from(settings.getAsList(ConfigConstants.LDAP_CUSTOM_ATTR_WHITELIST,
                Collections.singletonList("*")));
    }

    @Override
    @SuppressWarnings("removal")
    public User authenticate(final AuthCredentials credentials) throws OpenSearchSecurityException {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<User>() {
                @Override
                public User run() throws Exception {
                    return authenticate0(credentials);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getException() instanceof OpenSearchSecurityException) {
                throw (OpenSearchSecurityException) e.getException();
            } else if (e.getException() instanceof RuntimeException) {
                throw (RuntimeException) e.getException();
            } else {
                throw new RuntimeException(e.getException());
            }
        }
    }


    private User authenticate0(final AuthCredentials credentials) throws OpenSearchSecurityException {

        Connection ldapConnection = null;
        final String user = credentials.getUsername();
        byte[] password = credentials.getPassword();

        try {

            ldapConnection = connectionFactory.getConnection();
            ldapConnection.open();

            LdapEntry entry = userSearcher.exists(ldapConnection, user, this.returnAttributes, this.shouldFollowReferrals);

            // fake a user that no exists
            // makes guessing if a user exists or not harder when looking on the
            // authentication delay time
            if (entry == null && settings.getAsBoolean(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, false)) {
                String fakeLognDn = settings.get(ConfigConstants.LDAP_FAKE_LOGIN_DN,
                        "CN=faketomakebindfail,DC=" + UUID.randomUUID().toString());
                entry = new LdapEntry(fakeLognDn);
                password = settings.get(ConfigConstants.LDAP_FAKE_LOGIN_PASSWORD, "fakeLoginPwd123")
                        .getBytes(StandardCharsets.UTF_8);
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

            // by default all ldap attributes which are not binary and with a max value
            // length of 36 are included in the user object
            // if the whitelist contains at least one value then all attributes will be
            // additional check if whitelisted (whitelist can contain wildcard and regex)
            return new LdapUser(username, user, entry, credentials, customAttrMaxValueLen, whitelistedCustomLdapAttrMatcher);

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

    @SuppressWarnings("removal")
    @Override
    public boolean exists(final User user) {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }


        return AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            @Override
            public Boolean run() {
                return exists0(user);
            }
        });

    }

    private boolean exists0(final User user) {
        Connection ldapConnection = null;
        String userName = user.getName();

        if (user instanceof LdapUser) {
            userName = ((LdapUser) user).getUserEntry().getDn();
        }

        try {
            ldapConnection = this.connectionFactory.getConnection();
            ldapConnection.open();
            LdapEntry userEntry = this.userSearcher.exists(ldapConnection, userName, this.returnAttributes, this.shouldFollowReferrals);
            
            boolean exists = userEntry != null;
            
            if(exists) {
                user.addAttributes(LdapUser.extractLdapAttributes(userName, userEntry, customAttrMaxValueLen, whitelistedCustomLdapAttrMatcher));
            }
            
            return exists;
        } catch (final Exception e) {
            log.warn("User {} does not exist due to exception", userName, e);
            return false;
        } finally {
            Utils.unbindAndCloseSilently(ldapConnection);
        }
    }

    @SuppressWarnings("removal")
    private void authenticateByLdapServer(final Connection connection, final String dn, byte[] password)
            throws LdapException {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Response<Void>>() {
                @Override
                public Response<Void> run() throws LdapException {
                    return connection.getProviderConnection().bind(new BindRequest(dn, new Credential(password)));
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getException() instanceof LdapException) {
                throw (LdapException) e.getException();
            } else if (e.getException() instanceof RuntimeException) {
                throw (RuntimeException) e.getException();
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
