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

package com.floragunn.searchguard.authentication.backend.ldap;

import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.LdapUser;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.NonCachingAuthenticationBackend;
import com.floragunn.searchguard.authorization.ldap.LDAPAuthorizator;
import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;

public class LDAPAuthenticationBackend implements NonCachingAuthenticationBackend {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;

    @Inject
    public LDAPAuthenticationBackend(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public User authenticate(final AuthCredentials authCreds) throws AuthException {

        LdapConnection ldapConnection = null;
        final String user = authCreds.getUsername();

        final char[] password = authCreds.getPassword();
        authCreds.clear();

        EntryCursor result = null;

        try {

            ldapConnection = LDAPAuthorizator.getConnection(settings);

            final String bindDn = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_BIND_DN, null);

            if (bindDn != null) {
                ldapConnection.bind(bindDn, settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_PASSWORD, null));
            } else {
                ldapConnection.anonymousBind();
            }

            result = ldapConnection.search(settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_USERBASE, ""),
                    settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_USERSEARCH, "(sAMAccountName={0})").replace("{0}", user),
                    SearchScope.SUBTREE);

            if (!result.next()) {
                throw new AuthException("No user " + user + " found");
            }

            final Entry entry = result.get();
            final String dn = entry.getDn().toString();

            if (result.next()) {
                throw new AuthException("More than one user found");
            }

            log.trace("Disconnect {}", bindDn == null ? "anonymous" : bindDn);

            SecurityUtil.unbindAndCloseSilently(ldapConnection);
            ldapConnection = LDAPAuthorizator.getConnection(settings);

            log.trace("Try to authenticate dn {}", dn);

            ldapConnection.bind(dn, new String(password));

            final String usernameAttribute = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_USERNAME_ATTRIBUTE, null);
            String username = dn;

            if (usernameAttribute != null && entry.get(usernameAttribute) != null) {
                username = entry.get(usernameAttribute).getString();
            }

            log.debug("Authenticated username {}", username);

            return new LdapUser(username, entry);

        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new AuthException(e);
        } finally {
            if (result != null) {
                result.close();
            }

            SecurityUtil.unbindAndCloseSilently(ldapConnection);
        }

    }

}
