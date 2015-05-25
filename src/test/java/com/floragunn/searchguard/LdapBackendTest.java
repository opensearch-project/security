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

package com.floragunn.searchguard;

import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.LdapUser;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.ldap.LDAPAuthenticationBackend;
import com.floragunn.searchguard.authorization.GuavaCachingAuthorizator;
import com.floragunn.searchguard.authorization.ldap.LDAPAuthorizator;
import com.floragunn.searchguard.util.SecurityUtil;

public class LdapBackendTest extends AbstractUnitTest {

    @Test
    public void testLdapAuthentication() throws Exception {

        startLDAPServer();

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "123.xxx.1:838b9", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})").build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthenticationUserNameAttribute() throws Exception {

        startLDAPServer();

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "123.xxx.1:838b9", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.ldap.username_attribute", "uid")

                .build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("jacksonm", user.getName());
    }

    @Test
    public void testLdapAuthenticationSSL() throws Exception {

        startLDAPServer();

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapsServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.ldap.ldaps.ssl.enabled", "true")
                .put("searchguard.authentication.ldap.ldaps.starttls.enabled", "false")

                .put("searchguard.authentication.ldap.ldaps.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test(expected = AuthException.class)
    public void testLdapAuthenticationSSLWrongPwd() throws Exception {

        startLDAPServer();

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapsServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.ldap.ldaps.ssl.enabled", "true")
                .put("searchguard.authentication.ldap.ldaps.starttls.enabled", "false")

                .put("searchguard.authentication.ldap.ldaps.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm",
                "secret-wrong".toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthenticationStartTLS() throws Exception {

        startLDAPServer();

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.ldap.ldaps.ssl.enabled", "false")
                .put("searchguard.authentication.ldap.ldaps.starttls.enabled", "true")
                .put("searchguard.authentication.ldap.ldaps.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test(expected = AuthException.class)
    public void testLdapAuthenticationSSLPlainFail() throws Exception {

        startLDAPServer();

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapsServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.ldap.ldaps.ssl.enabled", "false")
                .put("searchguard.authentication.ldap.ldaps.starttls.enabled", "false")

                .put("searchguard.authentication.ldap.ldaps.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test(expected = AuthException.class)
    public void testLdapAuthenticationFail() throws Exception {
        startLDAPServer();
        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})").build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm",
                "secret-wrong".toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthorizationDN() throws Exception {
        startLDAPServer();
        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})").build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final User user = new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret".toCharArray()));
        Assert.assertTrue(user instanceof LdapUser);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials(user.getName(), null));
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals(2, ((LdapUser) user).getRoleEntries().size());
    }

    @Test(expected = AuthException.class)
    public void testLdapAuthorizationDNWithNonAnonBindFail() throws Exception {
        startLDAPServer();
        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("searchguard.authentication.ldap.bind_dn", "xxx").put("searchguard.authentication.ldap.password", "ccc").build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final User user = new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret".toCharArray()));
        Assert.assertTrue(user instanceof LdapUser);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials(user.getName(), null));
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals(2, ((LdapUser) user).getRoleEntries().size());

    }

    @Test
    public void testLdapAuthorizationDNWithNonAnonBind() throws Exception {
        startLDAPServer();
        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("searchguard.authentication.ldap.bind_dn", "cn=Captain Spock,ou=people,o=TEST")
                .put("searchguard.authentication.ldap.password", "spocksecret").build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final User user = new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret".toCharArray()));
        Assert.assertTrue(user instanceof LdapUser);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials(user.getName(), null));
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals(2, ((LdapUser) user).getRoleEntries().size());

    }

    @Test
    public void testLdapAuthorization() throws Exception {
        startLDAPServer();
        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})").build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final LdapUser user = new LdapUser("jacksonm", null);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials("jacksonm", null));
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals(2, user.getRoleEntries().size());

    }

    @Test
    public void testLdapAuthorizationUserRoles() throws Exception {
        startLDAPServer();
        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("searchguard.authentication.authorization.ldap.userrolename", "description").build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final LdapUser user = new LdapUser("jacksonm", null);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials("jacksonm", null));
        Assert.assertEquals(3, user.getRoles().size());
        Assert.assertEquals(3, user.getRoleEntries().size());

    }

    @Test
    public void testLdapAuthorizationNestedRoles() throws Exception {
        startLDAPServer();
        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("searchguard.authentication.authorization.ldap.resolve_nested_roles", true)

                .build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final LdapUser user = new LdapUser("spock", null);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials("spock", null));
        Assert.assertEquals(4, user.getRoles().size());
        Assert.assertEquals(4, user.getRoleEntries().size());
    }

    @Test
    public void testLdapAuthorizationNestedRolesCache() throws Exception {
        startLDAPServer();
        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("searchguard.authentication.authorization.ldap.resolve_nested_roles", true)

                .build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        LdapUser user = new LdapUser("spock", null);
        final GuavaCachingAuthorizator gc = new GuavaCachingAuthorizator(new LDAPAuthorizator(settings), settings);
        gc.fillRoles(user, new AuthCredentials("spock", null));
        user = new LdapUser("spock", null);
        gc.fillRoles(user, new AuthCredentials("spock", null));
        Assert.assertEquals(4, user.getRoles().size());
        Assert.assertEquals(4, user.getRoleEntries().size());
    }

    @Test
    public void testLdapAuthorizationNestedRolesOff() throws Exception {
        startLDAPServer();
        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("searchguard.authentication.authorization.ldap.resolve_nested_roles", false)

                .build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final LdapUser user = new LdapUser("spock", null);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials("spock", null));
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals(2, user.getRoleEntries().size());

    }
}
