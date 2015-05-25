/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.authorization.ldap;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.TrustManagerFactory;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.elasticsearch.common.collect.Iterators;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.LdapUser;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authorization.NonCachingAuthorizator;
import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;

public class LDAPAuthorizator implements NonCachingAuthorizator {

    protected static final ESLogger log = Loggers.getLogger(LDAPAuthorizator.class);
    final Settings settings;

    @Inject
    public LDAPAuthorizator(final Settings settings) {

        this.settings = settings;

    }

    public static LdapConnection getConnection(final Settings settings) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException, LdapException {
        final boolean useSSL = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_LDAPS_SSL_ENABLED, false);
        final boolean useStartSSL = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_LDAPS_STARTTLS_ENABLED, false);
        final LdapConnectionConfig config = new LdapConnectionConfig();

        if (useSSL || useStartSSL) {
            //## Truststore ##
            final KeyStore ts = KeyStore.getInstance(settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_TYPE,
                    "JKS"));
            ts.load(new FileInputStream(new File(settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_FILEPATH,
                    null))), settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_PASSWORD, "changeit")
                    .toCharArray());

            final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            config.setSslProtocol("TLS");
            config.setEnabledCipherSuites(SecurityUtil.ENABLED_SSL_CIPHERS);
            config.setTrustManagers(tmf.getTrustManagers());
        }

        config.setUseSsl(useSSL);
        config.setUseTls(useStartSSL);
        config.setTimeout(5000L); //5 sec

        final String[] ldapHosts = settings.getAsArray(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_HOST, new String[] { "localhost" });

        LdapConnection ldapConnection = null;

        for (int i = 0; i < ldapHosts.length; i++) {
            log.trace("Connect to {}", ldapHosts[i]);

            try {

                final String[] split = ldapHosts[i].split(":");

                config.setLdapHost(split[0]);

                if (split.length > 1) {
                    config.setLdapPort(Integer.parseInt(split[1]));
                } else {
                    config.setLdapPort(useSSL ? 636 : 389);
                }

                ldapConnection = new LdapNetworkConnection(config);
                ldapConnection.connect();
                if (!ldapConnection.isConnected()) {
                    continue;
                } else {
                    break;
                }

            } catch (final Exception e) {
                continue;
            }
        }

        if (ldapConnection == null || !ldapConnection.isConnected()) {
            throw new LdapException("Unable to connect to any of those ldap servers " + Arrays.toString(ldapHosts));
        }

        return ldapConnection;
    }

    @Override
    public void fillRoles(final User user, final AuthCredentials optionalAuthCreds) throws AuthException {

        final String authenticatedUser = user.getName();

        if (optionalAuthCreds != null) {
            optionalAuthCreds.clear();
        }

        Entry entry = null;
        String dn = null;
        EntryCursor result = null;
        EntryCursor rolesResult = null;
        LdapConnection ldapConnection = null;

        try {

            ldapConnection = getConnection(settings);

            final String bindDn = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_BIND_DN, null);

            if (bindDn != null) {
                ldapConnection.bind(bindDn, settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_PASSWORD, null));
            } else {
                ldapConnection.anonymousBind();
            }

            if (Dn.isValid(authenticatedUser)) {
                //assume dn
                log.trace("{} is a valid DN", authenticatedUser);
                entry = ldapConnection.lookup(authenticatedUser);

                if (entry == null) {
                    throw new AuthException("No user '" + authenticatedUser + "' found");
                }

            } else {

                //TODO FUTURE all ldap searches: follow referrals
                result = ldapConnection.search(
                        settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_USERBASE, ""),
                        settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_USERSEARCH, "(sAMAccountName={0})").replace("{0}",
                                authenticatedUser), SearchScope.SUBTREE);

                if (!result.next()) {
                    throw new AuthException("No user '" + authenticatedUser + "' found");
                }

                entry = result.get();

                if (result.next()) {
                    throw new AuthException("More than user found");
                }

            }

            dn = entry.getDn().toString();

            log.trace("User found with DN {}", dn);

            final Set<String> userRolesDn = new HashSet<String>();

            //Roles as an attribute of the user entry
            //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.
            final String userRoleName = settings
                    .get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLENAME, "memberOf");
            if (entry.get(userRoleName) != null) {
                final Value[] userRoles = Iterators.toArray(entry.get(userRoleName).iterator(), Value.class);

                for (int i = 0; i < userRoles.length; i++) {
                    final Value value = userRoles[i];
                    final String possibleRoleDN = value.getString();
                    if (Dn.isValid(possibleRoleDN)) {
                        userRolesDn.add(possibleRoleDN);
                    }
                }

                log.trace("User roles count: {}", userRolesDn.size());
            }

            final Map<Tuple<String, Dn>, Entry> roles = new HashMap<Tuple<String, Dn>, Entry>();
            final String roleName = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_ROLENAME, "name");

            //replace {2}
            final String userRoleAttribute = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLEATTRIBUTE,
                    null);
            String userRoleAttributeValue = null;

            if (userRoleAttribute != null) {
                userRoleAttributeValue = entry.get(userRoleAttribute) == null ? null : entry.get(userRoleAttribute).getString();
            }

            rolesResult = ldapConnection.search(
                    settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_ROLEBASE, ""),
                    settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_ROLESEARCH, "(member={0})")
                            .replace("{0}", dn).replace("{1}", authenticatedUser)
                            .replace("{2}", userRoleAttributeValue == null ? "{2}" : userRoleAttributeValue), SearchScope.SUBTREE);

            for (final Iterator iterator = rolesResult.iterator(); iterator.hasNext();) {
                final Entry searchResultEntry = (Entry) iterator.next();
                roles.put(new Tuple<String, Dn>(searchResultEntry.getDn().toString(), searchResultEntry.getDn()), searchResultEntry);
            }

            log.trace("non user roles count: {}", roles.size());

            for (final Iterator<String> it = userRolesDn.iterator(); it.hasNext();) {
                final String stringVal = it.next();
                //lookup
                final Entry userRole = ldapConnection.lookup(stringVal);
                roles.put(new Tuple<String, Dn>(stringVal, null), userRole);

            }

            //nested roles
            if (settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_RESOLVE_NESTED_ROLES, false)) {

                log.trace("Evaluate nested roles");

                final Set<Entry> nestedReturn = new HashSet<Entry>(roles.values());

                for (final Iterator<java.util.Map.Entry<Tuple<String, Dn>, Entry>> iterator = roles.entrySet().iterator(); iterator
                        .hasNext();) {
                    final java.util.Map.Entry<Tuple<String, Dn>, Entry> _entry = iterator.next();

                    final Set<Entry> x = resolveNestedRoles(_entry.getKey(), ldapConnection, roleName);

                    log.trace("{}. nested roles for {} {}", x.size(), _entry.getKey(), roleName);

                    nestedReturn.addAll(x);

                }

                for (final Iterator iterator = nestedReturn.iterator(); iterator.hasNext();) {
                    final Entry entry2 = (Entry) iterator.next();
                    final String role = entry2.get(roleName).getString();
                    user.addRole(role);
                }

                if (user instanceof LdapUser) {
                    ((LdapUser) user).addRoleEntries(nestedReturn);
                }

            } else {

                for (final Iterator iterator = roles.values().iterator(); iterator.hasNext();) {
                    final Entry entry2 = (Entry) iterator.next();
                    final String role = entry2.get(roleName).getString();
                    user.addRole(role);
                }

                if (user instanceof LdapUser) {
                    ((LdapUser) user).addRoleEntries(roles.values());
                }
            }

        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new AuthException(e);
        } finally {
            if (result != null) {
                result.close();
            }

            if (rolesResult != null) {
                rolesResult.close();
            }

            SecurityUtil.unbindAndCloseSilently(ldapConnection);
        }

    }

    protected Set<Entry> resolveNestedRoles(final Tuple<String, Dn> role, final LdapConnection ldapConnection, final String roleName)
            throws AuthException, LdapException {

        EntryCursor rolesResult = null;
        EntryCursor _result = null;
        try {

            final Set<Entry> result = new HashSet<Entry>();
            Dn roleDn = null;
            final boolean isRoleStringValidDn = Dn.isValid(role.v1());

            if (role.v2() != null) {
                roleDn = role.v2();
            } else {
                //lookup role
                if (isRoleStringValidDn) {
                    roleDn = ldapConnection.lookup(role.v1()).getDn();
                } else {

                    try {

                        //search
                        _result = ldapConnection.search(settings.get(
                                ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_ROLEBASE, ""),
                                settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_ROLESEARCH, "(member={0})")
                                        .replace("{1}", role.v1()), SearchScope.SUBTREE);

                        //one
                        if (!_result.next()) {
                            log.warn("Cannot resolve role '{}' (NOT FOUND)", role.v1());
                        } else {

                            //
                            final Entry entry = _result.get();
                            roleDn = entry.getDn();

                            if (_result.next()) {
                                log.warn("Cannot resolve role '{}' (MORE THAN ONE FOUND)", role.v1());
                            }

                        }
                    } catch (final CursorException e) {
                        log.warn("Cannot resolve role '{}' (EXCEPTION: {})", e, role.v1(), e.toString());
                    } finally {
                        if (_result != null) {
                            _result.close();
                        }

                    }

                }

            }

            log.trace("role dn resolved to {}", roleDn);

            rolesResult = ldapConnection.search(
                    settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_ROLEBASE, ""),
                    settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_ROLESEARCH, "(member={0})")
                            .replace("{0}", roleDn == null ? role.v1() : roleDn.toString()).replace("{1}", role.v1()), SearchScope.SUBTREE);

            for (final Iterator iterator = rolesResult.iterator(); iterator.hasNext();) {
                final Entry searchResultEntry = (Entry) iterator.next();
                final String _role = searchResultEntry.get(roleName).getString();
                log.trace("nested l1 {}", searchResultEntry.getDn());
                final Set<Entry> in = resolveNestedRoles(new Tuple<String, Dn>(_role, searchResultEntry.getDn()), ldapConnection, roleName);

                for (final Iterator<Entry> iterator2 = in.iterator(); iterator2.hasNext();) {
                    final Entry entry = iterator2.next();
                    result.add(entry);
                    log.trace("nested l2 {}", entry.getDn());
                }

                result.add(searchResultEntry);

            }

            return result;
        } finally {

            if (rolesResult != null) {
                rolesResult.close();
            }
        }
    }

}
