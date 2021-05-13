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

package com.amazon.dlic.auth.ldap;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.TreeSet;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.ldaptive.Connection;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;

import com.amazon.dlic.auth.ldap.backend.LDAPAuthenticationBackend;
import com.amazon.dlic.auth.ldap.backend.LDAPAuthorizationBackend;
import com.amazon.dlic.auth.ldap.srv.EmbeddedLDAPServer;
import com.amazon.dlic.auth.ldap.util.ConfigConstants;
import com.amazon.dlic.auth.ldap.util.LdapHelper;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

public class LdapBackendTest {

    static {
        System.setProperty("security.display_lic_none", "true");
    }

    private static EmbeddedLDAPServer ldapServer = null;
    private static int ldapPort;
    private static int ldapsPort;

    @BeforeClass
    public static void startLdapServer() throws Exception {
        ldapServer = new EmbeddedLDAPServer();
        ldapServer.start();
        ldapServer.applyLdif("base.ldif");
        ldapPort = ldapServer.getLdapPort();
        ldapsPort = ldapServer.getLdapsPort();
    }

    @Test
    public void testLdapAuthentication() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test(expected=OpenSearchSecurityException.class)
    public void testLdapAuthenticationFakeLogin() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, true)
                .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("unknown", "unknown"
                .getBytes(StandardCharsets.UTF_8)));
    }

    @Test(expected=OpenSearchSecurityException.class)
    public void testLdapInjection() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        String injectString = "*jack*";


        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials(injectString, "secret"
                .getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testLdapAuthenticationBindDn() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS,  "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_BIND_DN, "cn=Captain Spock,ou=people,o=TEST")
                .put(ConfigConstants.LDAP_PASSWORD, "spocksecret")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test(expected=OpenSearchSecurityException.class)
    public void testLdapAuthenticationWrongBindDn() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS,  "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_BIND_DN, "cn=Captain Spock,ou=people,o=TEST")
                .put(ConfigConstants.LDAP_PASSWORD, "wrong")
                .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
    }

    @Test(expected=OpenSearchSecurityException.class)
    public void testLdapAuthenticationBindFail() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS,  "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "wrong".getBytes(StandardCharsets.UTF_8)));
    }

    @Test(expected=OpenSearchSecurityException.class)
    public void testLdapAuthenticationNoUser() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS,  "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("UNKNOWN", "UNKNOWN".getBytes(StandardCharsets.UTF_8)));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationFail() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "xxxxx".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testLdapAuthenticationSSL() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put("opendistro_security.ssl.transport.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks"))
                .put("verify_hostnames", false)
                .put("path.home",".")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthenticationSSLPEMFile() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put(ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ldap/root-ca.pem").toFile().getName())
                .put("verify_hostnames", false)
                .put("path.home",".")
                .put("path.conf",FileHelper.getAbsoluteFilePathFromClassPath("ldap/root-ca.pem").getParent())
                .build();
        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, Paths.get("src/test/resources/ldap")).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthenticationSSLPEMText() throws Exception {
        final Settings settingsFromFile = Settings
                .builder()
                .loadFromPath(
                        Paths
                        .get(FileHelper
                                .getAbsoluteFilePathFromClassPath("ldap/test1.yml")
                                .toFile()
                                .getAbsolutePath()))
                .build();
        Settings settings = Settings.builder().put(settingsFromFile).putList("hosts", "localhost:"+ldapsPort).build();
        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthenticationSSLSSLv3() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put("opendistro_security.ssl.transport.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks"))
                .put("verify_hostnames", false)
                .putList("enabled_ssl_protocols", "SSLv3")
                .put("path.home",".")
                .build();

        try {
            new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                    .getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            Assert.assertEquals(e.getCause().getClass(), org.ldaptive.LdapException.class);
            Assert.assertTrue(e.getCause().getMessage().contains("Unable to connec"));
        }

    }

    @Test
    public void testLdapAuthenticationSSLUnknowCipher() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put("opendistro_security.ssl.transport.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks"))
                .put("verify_hostnames", false)
                .putList("enabled_ssl_ciphers", "AAA")
                .put("path.home",".")
                .build();

        try {
            new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                    .getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            Assert.assertEquals(e.getCause().getClass(), org.ldaptive.LdapException.class);
            Assert.assertTrue(e.getCause().getMessage().contains("Unable to connec"));
        }

    }

    @Test
    public void testLdapAuthenticationSpecialCipherProtocol() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put("opendistro_security.ssl.transport.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks"))
                .put("verify_hostnames", false)
                .putList("enabled_ssl_protocols", "TLSv1")
                .putList("enabled_ssl_ciphers", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA")
                .put("path.home",".")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());

    }

    @Test
    public void testLdapAuthenticationSSLNoKeystore() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put("opendistro_security.ssl.transport.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks"))
                .put("verify_hostnames", false)
                .put("path.home",".")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthenticationSSLFailPlain() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true).build();

        try {
            new LDAPAuthenticationBackend(settings, null)
                    .authenticate(new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8)));
        } catch (final Exception e) {
            Assert.assertEquals(org.ldaptive.LdapException.class, e.getCause().getClass());
        }
    }

    @Test
    public void testLdapExists() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        final LDAPAuthenticationBackend lbe = new LDAPAuthenticationBackend(settings, null);
        Assert.assertTrue(lbe.exists(new User("jacksonm")));
        Assert.assertFalse(lbe.exists(new User("doesnotexist")));
    }

    @Test
    public void testLdapAuthorization() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                // .put("opendistro_security.authentication.authorization.ldap.userrolename",
                // "(uniqueMember={0})")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("ceo", new ArrayList(new TreeSet(user.getRoles())).get(0));
        Assert.assertEquals(user.getName(), user.getUserEntry().getDn());
    }

    @Test
    public void testLdapAuthenticationReferral() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        final Connection con = LDAPAuthorizationBackend.getConnection(settings, null);
        try {
            final LdapEntry ref1 = LdapHelper.lookup(con, "cn=Ref1,ou=people,o=TEST");
            Assert.assertEquals("cn=refsolved,ou=people,o=TEST", ref1.getDn());
        } finally {
            con.close();
        }

    }


    @Test
    public void testLdapEscape() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("ssign", "ssignsecret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Special\\, Sign,ou=people,o=TEST", user.getName());
        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);
        Assert.assertEquals("cn=Special\\, Sign,ou=people,o=TEST", user.getName());
        Assert.assertEquals(4, user.getRoles().size());
        Assert.assertTrue(user.getRoles().toString().contains("ceo"));
    }

    @Test
    public void testLdapAuthorizationRoleSearchUsername() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(cn={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember=cn={1},ou=people,o=TEST)")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("Michael Jackson", "secret"
                .getBytes(StandardCharsets.UTF_8)));

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("Michael Jackson", user.getOriginalUsername());
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getUserEntry().getDn());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("ceo", new ArrayList(new TreeSet(user.getRoles())).get(0));
        Assert.assertEquals(user.getName(), user.getUserEntry().getDn());
    }

    @Test
    public void testLdapAuthorizationOnly() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .build();

        final User user = new User("jacksonm");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("jacksonm", user.getName());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("ceo", new ArrayList(new TreeSet(user.getRoles())).get(0));
    }


    @Test
    public void testLdapAuthorizationNonDNEntry() throws Exception {

        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "description")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .build();

        final User user = new User("jacksonm");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("jacksonm", user.getName());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("ceo-ceo", new ArrayList(new TreeSet(user.getRoles())).get(0));
    }


    @Test
    public void testLdapAuthorizationNested() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("spock", user.getName());
        Assert.assertEquals(4, user.getRoles().size());
        Assert.assertEquals("nested1", new ArrayList(new TreeSet(user.getRoles())).get(1));
    }

    @Test
    public void testLdapAuthorizationNestedFilter() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .putList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER, "cn=nested2,ou=groups,o=TEST")
                .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("spock", user.getName());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("ceo", new ArrayList(new TreeSet(user.getRoles())).get(0));
        Assert.assertEquals("nested2", new ArrayList(new TreeSet(user.getRoles())).get(1));
    }

    @Test
    public void testLdapAuthorizationDnNested() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "dn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("spock", user.getName());
        Assert.assertEquals(4, user.getRoles().size());
        Assert.assertEquals("cn=nested1,ou=groups,o=TEST", new ArrayList(new TreeSet(user.getRoles())).get(1));
    }

    @Test
    public void testLdapAuthorizationDn() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "dn")
                .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "UID")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .build();

        final User user = new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret".getBytes()));

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("jacksonm", user.getName());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("cn=ceo,ou=groups,o=TEST", new ArrayList(new TreeSet(user.getRoles())).get(0));
    }

    @Test
    public void testLdapAuthenticationUserNameAttribute() throws Exception {


        final Settings settings = Settings.builder().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST").put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid").build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("jacksonm", user.getName());
    }

    @Test
    public void testLdapAuthenticationStartTLS() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_START_TLS, true)
                .put("opendistro_security.ssl.transport.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks"))
                .put("verify_hostnames", false).put("path.home", ".")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthorizationSkipUsers() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .putList(ConfigConstants.LDAP_AUTHZ_SKIP_USERS, "cn=Michael Jackson,ou*people,o=TEST")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
        Assert.assertEquals(0, user.getRoles().size());
        Assert.assertEquals(user.getName(), user.getUserEntry().getDn());
    }

    @Test
    public void testLdapAuthorizationSkipUsersNoDn() throws Exception {

        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .putList(ConfigConstants.LDAP_AUTHZ_SKIP_USERS, "jacksonm")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
        Assert.assertEquals(0, user.getRoles().size());
        Assert.assertEquals(user.getName(), user.getUserEntry().getDn());
    }

    @Test
    public void testLdapAuthorizationNestedAttr() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
                .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("spock", user.getName());
        Assert.assertEquals(8, user.getRoles().size());
        Assert.assertEquals("nested3", new ArrayList(new TreeSet(user.getRoles())).get(4));
        Assert.assertEquals("rolemo4", new ArrayList(new TreeSet(user.getRoles())).get(7));
    }

    @Test
    public void testLdapAuthorizationNestedAttrFilter() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
                .putList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER, "cn=rolemo4*")
                .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("spock", user.getName());
        Assert.assertEquals(6, user.getRoles().size());
        Assert.assertEquals("role2", new ArrayList(new TreeSet(user.getRoles())).get(4));
        Assert.assertEquals("nested1", new ArrayList(new TreeSet(user.getRoles())).get(2));

    }

    @Test
    public void testLdapAuthorizationNestedAttrFilterAll() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
                .putList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER, "*")
                .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("spock", user.getName());
        Assert.assertEquals(4, user.getRoles().size());

    }

    @Test
    public void testLdapAuthorizationNestedAttrFilterAllEqualsNestedFalse() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false) //-> same like putList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER, "*")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
                .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("spock", user.getName());
        Assert.assertEquals(4, user.getRoles().size());

    }

    @Test
    public void testLdapAuthorizationNestedAttrNoRoleSearch() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "unused")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(((unused")
                .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, false)
                .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("spock", user.getName());
        Assert.assertEquals(3, user.getRoles().size());
        Assert.assertEquals("nested3", new ArrayList(new TreeSet(user.getRoles())).get(1));
        Assert.assertEquals("rolemo4", new ArrayList(new TreeSet(user.getRoles())).get(2));
    }

    @Test
    public void testCustomAttributes() throws Exception {

        Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
        Assert.assertEquals(user.getCustomAttributesMap().toString(), 16, user.getCustomAttributesMap().size());
        Assert.assertFalse(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().keySet().contains("attr.ldap.userpassword"));

        settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 0)
                .build();

        user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));

        Assert.assertEquals(user.getCustomAttributesMap().toString(), 2, user.getCustomAttributesMap().size());

        settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .putList(ConfigConstants.LDAP_CUSTOM_ATTR_WHITELIST, "*objectclass*","entryParentId")
                .build();

        user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));

        Assert.assertEquals(user.getCustomAttributesMap().toString(), 2, user.getCustomAttributesMap().size());

    }

    @Test
    public void testLdapAuthorizationNonDNRoles() throws Exception {

        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description, ou") // no memberOf OID
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
                .build();

        final User user = new User("nondnroles");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("nondnroles", user.getName());
        Assert.assertEquals(5, user.getRoles().size());
        Assert.assertTrue("Roles do not contain non-LDAP role 'kibanauser'", user.getRoles().contains("kibanauser"));
        Assert.assertTrue("Roles do not contain non-LDAP role 'humanresources'", user.getRoles().contains("humanresources"));
        Assert.assertTrue("Roles do not contain LDAP role 'dummyempty'", user.getRoles().contains("dummyempty"));
        Assert.assertTrue("Roles do not contain non-LDAP role 'role2'", user.getRoles().contains("role2"));
        Assert.assertTrue("Roles do not contain non-LDAP role 'anotherrole' from second role name", user.getRoles().contains("anotherrole"));
    }


    @Test
    public void testLdapSpecial186() throws Exception {

        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "description")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("spec186", "spec186"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST", user.getName());
        Assert.assertEquals("AA BB/CC (DD) my, company end=with=whitespace ", user.getUserEntry().getAttribute("cn").getStringValue());
        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertEquals(3, user.getRoles().size());
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLEx(186n) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186nn) consists of\\, special="));

        new LDAPAuthorizationBackend(settings, null).fillRoles(new User("spec186"), null);
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLEx(186n) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186nn) consists of\\, special="));

        new LDAPAuthorizationBackend(settings, null).fillRoles(new User("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"), null);
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLEx(186n) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186nn) consists of\\, special="));

        new LDAPAuthorizationBackend(settings, null).fillRoles(new User("CN=AA BB\\/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"), null);
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLEx(186n) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186nn) consists of\\, special="));
    }

    @Test
    public void testLdapSpecial186_2() throws Exception {

        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "dn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("spec186", "spec186"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST", user.getName());
        Assert.assertEquals("AA BB/CC (DD) my, company end=with=whitespace ", user.getUserEntry().getAttribute("cn").getStringValue());
        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertEquals(3, user.getRoles().size());
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));

        new LDAPAuthorizationBackend(settings, null).fillRoles(new User("spec186"), null);
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));


        new LDAPAuthorizationBackend(settings, null).fillRoles(new User("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"), null);
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));

        new LDAPAuthorizationBackend(settings, null).fillRoles(new User("CN=AA BB\\/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"), null);
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));
    }

    @Test
    public void testOperationalAttributes() throws Exception {


        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        LdapAttribute operationAttribute = user.getUserEntry().getAttribute("entryUUID");
        Assert.assertNotNull(operationAttribute);
        Assert.assertNotNull(operationAttribute.getStringValue());
        Assert.assertTrue(operationAttribute.getStringValue().length() > 10);
        Assert.assertTrue(operationAttribute.getStringValue().split("-").length == 5);
    }

    @Test
    public void testMultiCn() throws Exception {

        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("multi", "multi"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=cabc,ou=people,o=TEST", user.getName());
        System.out.println(user.getUserEntry().getAttribute("cn"));
    }


    @AfterClass
    public static void tearDown() throws Exception {

        if (ldapServer != null) {
            ldapServer.stop();
        }

    }
}
