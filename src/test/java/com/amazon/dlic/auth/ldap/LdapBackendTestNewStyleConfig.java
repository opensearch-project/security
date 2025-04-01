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

package com.amazon.dlic.auth.ldap;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.TreeSet;

import org.hamcrest.MatcherAssert;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import com.amazon.dlic.auth.ldap.backend.LDAPAuthenticationBackend;
import com.amazon.dlic.auth.ldap.backend.LDAPAuthorizationBackend;
import com.amazon.dlic.auth.ldap.srv.EmbeddedLDAPServer;
import com.amazon.dlic.auth.ldap.util.ConfigConstants;
import com.amazon.dlic.auth.ldap.util.LdapHelper;
import org.ldaptive.Connection;
import org.ldaptive.LdapEntry;
import org.ldaptive.ReturnAttributes;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;

public class LdapBackendTestNewStyleConfig {

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
        ldapServer.applyLdif("base.ldif", "base2.ldif");
        ldapPort = ldapServer.getLdapPort();
        ldapsPort = ldapServer.getLdapsPort();
    }

    @Test
    public void testLdapAuthentication() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationFakeLogin() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, true)
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("unknown", "unknown".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapInjection() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .build();

        String injectString = "*jack*";

        @SuppressWarnings("unused")
        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials(injectString, "secret".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test
    public void testLdapAuthenticationBindDn() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_BIND_DN, "cn=Captain Spock,ou=people,o=TEST")
            .put(ConfigConstants.LDAP_PASSWORD, "spocksecret")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationWrongBindDn() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_BIND_DN, "cn=Captain Spock,ou=people,o=TEST")
            .put(ConfigConstants.LDAP_PASSWORD, "wrong")
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationBindFail() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "wrong".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationNoUser() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("UNKNOWN", "UNKNOWN".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationFail() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "xxxxx".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test
    public void testLdapAuthenticationSSL() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLPEMFile() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/root-ca.pem").toFile().getName()
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .put("path.conf", FileHelper.getAbsoluteFilePathFromClassPath("ldap/root-ca.pem").getParent())
            .build();
        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, Paths.get("src/test/resources/ldap")).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLPEMText() throws Exception {

        final Settings settingsFromFile = Settings.builder()
            .loadFromPath(Paths.get(FileHelper.getAbsoluteFilePathFromClassPath("ldap/test1.yml").toFile().getAbsolutePath()))
            .build();
        Settings settings = Settings.builder().put(settingsFromFile).putList("hosts", "localhost:" + ldapsPort).build();
        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLSSLv3() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .putList("enabled_ssl_protocols", "SSLv3")
            .put("path.home", ".")
            .build();

        try {
            new LDAPAuthenticationBackend(settings, null).authenticate(
                new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
            );
        } catch (Exception e) {
            assertThat(org.ldaptive.LdapException.class, is(e.getCause().getClass()));
            Assert.assertTrue(e.getCause().getMessage().contains("Unable to connec"));
        }

    }

    @Test
    public void testLdapAuthenticationSSLUnknownCipher() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .putList("enabled_ssl_ciphers", "AAA")
            .put("path.home", ".")
            .build();

        try {
            new LDAPAuthenticationBackend(settings, null).authenticate(
                new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
            );
        } catch (Exception e) {
            assertThat(org.ldaptive.LdapException.class, is(e.getCause().getClass()));
            Assert.assertTrue(e.getCause().getMessage().contains("Unable to connec"));
        }

    }

    @Test
    public void testLdapAuthenticationSpecialCipherProtocol() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .putList("enabled_ssl_protocols", "TLSv1.2")
            .putList("enabled_ssl_ciphers", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA")
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));

    }

    @Test
    public void testLdapAuthenticationSSLNoKeystore() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLFailPlain() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .build();

        try {
            new LDAPAuthenticationBackend(settings, null).authenticate(
                new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
            );
        } catch (final Exception e) {
            assertThat(e.getCause().getClass(), is(org.ldaptive.LdapException.class));
        }
    }

    @Test
    public void testLdapExists() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .build();

        final LDAPAuthenticationBackend lbe = new LDAPAuthenticationBackend(settings, null);
        Assert.assertTrue(lbe.impersonate(new User("jacksonm")).isPresent());
        Assert.assertFalse(lbe.impersonate(new User("doesnotexist")).isPresent());
    }

    @Test
    public void testLdapAuthorization() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put("roles.g1.search", "(uniqueMember={0})")
            // .put("plugins.security.authentication.authorization.ldap.userrolename",
            // "(uniqueMember={0})")
            .build();

        final LdapUser ldapUser = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(ldapUser, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(2));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(0), is("ceo"));
        assertThat(ldapUser.getUserEntry().getDn(), is(user.getName()));
    }

    @Test
    public void testLdapAuthenticationReferral() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .build();

        final Connection con = LDAPAuthorizationBackend.getConnection(settings, null);
        try {
            final LdapEntry ref1 = LdapHelper.lookup(con, "cn=Ref1,ou=people,o=TEST", ReturnAttributes.ALL.value(), true);
            assertThat(ref1.getDn(), is("cn=refsolved,ou=people,o=TEST"));
        } finally {
            con.close();
        }

    }

    @Test
    public void testLdapDontFollowReferrals() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.FOLLOW_REFERRALS, false)
            .build();

        final Connection con = LDAPAuthorizationBackend.getConnection(settings, null);
        try {
            // If following is off then should fail to return the result provided by following
            final LdapEntry ref1 = LdapHelper.lookup(
                con,
                "cn=Ref1,ou=people,o=TEST",
                ReturnAttributes.ALL.value(),
                settings.getAsBoolean(ConfigConstants.FOLLOW_REFERRALS, ConfigConstants.FOLLOW_REFERRALS_DEFAULT)
            );
            Assert.assertNull(ref1);
        } finally {
            con.close();
        }
    }

    @Test
    public void testLdapEscape() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put("roles.g1.search", "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .build();

        User user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("ssign", "ssignsecret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Special\\, Sign,ou=people,o=TEST"));
        user = new LDAPAuthorizationBackend(settings, null).addRoles(user, null);
        assertThat(user.getName(), is("cn=Special\\, Sign,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(4));
        Assert.assertTrue(user.getRoles().toString().contains("ceo"));
    }

    @Test
    public void testLdapAuthorizationRoleSearchUsername() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(cn={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put("roles.g1.search", "(uniqueMember=cn={1},ou=people,o=TEST)")
            .build();

        final LdapUser ldapUser = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("Michael Jackson", "secret".getBytes(StandardCharsets.UTF_8))
        );

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(ldapUser, null);

        Assert.assertNotNull(user);
        assertThat(ldapUser.getOriginalUsername(), is("Michael Jackson"));
        assertThat(ldapUser.getUserEntry().getDn(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(2));
        MatcherAssert.assertThat(user.getRoles(), hasItem("ceo"));
        assertThat(ldapUser.getUserEntry().getDn(), is(user.getName()));
    }

    @Test
    public void testLdapAuthorizationOnly() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put("roles.g1.search", "(uniqueMember={0})")
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("jacksonm"), null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
        assertThat(user.getRoles().size(), is(2));
        MatcherAssert.assertThat(user.getRoles(), hasItem("ceo"));
    }

    @Test
    public void testLdapAuthorizationNested() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put("roles.g1.search", "(uniqueMember={0})")
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));
        MatcherAssert.assertThat(user.getRoles(), hasItem("nested1"));
    }

    @Test
    public void testLdapAuthorizationNestedFilter() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put("roles.g1.search", "(uniqueMember={0})")
            .putList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER, "cn=nested2,ou=groups,o=TEST")
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(2));
        MatcherAssert.assertThat(user.getRoles(), hasItem("ceo"));
        MatcherAssert.assertThat(user.getRoles(), hasItem("nested2"));
    }

    @Test
    public void testLdapAuthorizationDnNested() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "dn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put("roles.g1.search", "(uniqueMember={0})")
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));
        MatcherAssert.assertThat(user.getRoles(), hasItem("cn=nested1,ou=groups,o=TEST"));
    }

    @Test
    public void testLdapAuthorizationDn() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "dn")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "UID")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false)
            .put("roles.g1.search", "(uniqueMember={0})")
            .build();

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(new AuthCredentials("jacksonm", "secret".getBytes()));

        user = new LDAPAuthorizationBackend(settings, null).addRoles(user, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
        assertThat(user.getRoles().size(), is(2));
        MatcherAssert.assertThat(user.getRoles(), hasItem("cn=ceo,ou=groups,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationUserNameAttribute() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.base", "ou=people,o=TEST")
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
    }

    @Test
    public void testLdapAuthenticationStartTLS() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_START_TLS, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthorizationSkipUsers() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put("roles.g1.search", "(uniqueMember={0})")
            .putList(ConfigConstants.LDAP_AUTHZ_SKIP_USERS, "cn=Michael Jackson,ou*people,o=TEST")
            .build();

        final LdapUser ldapUser = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(ldapUser, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(0));
        assertThat(ldapUser.getUserEntry().getDn(), is(user.getName()));
    }

    @Test
    public void testLdapAuthorizationNestedAttr() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put("roles.g1.search", "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(8));
        MatcherAssert.assertThat(user.getRoles(), hasItem("nested3"));
        MatcherAssert.assertThat(user.getRoles(), hasItem("rolemo4"));
    }

    @Test
    public void testLdapAuthorizationNestedAttrFilter() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put("roles.g1.search", "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
            .putList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER, "cn=rolemo4*")
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(6));
        MatcherAssert.assertThat(user.getRoles(), hasItem("role2"));
        MatcherAssert.assertThat(user.getRoles(), hasItem("nested1"));

    }

    @Test
    public void testLdapAuthorizationNestedAttrFilterAll() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put("roles.g1.search", "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
            .putList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER, "*")
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));

    }

    @Test
    public void testLdapAuthorizationNestedAttrFilterAllEqualsNestedFalse() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false) // -> same like
                                                                         // putList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER,
                                                                         // "*")
            .put("roles.g1.search", "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));

    }

    @Test
    public void testLdapAuthorizationNestedAttrNoRoleSearch() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "unused")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put("roles.g1.search", "(((unused")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, false)
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(3));
        MatcherAssert.assertThat(user.getRoles(), hasItem("nested3"));
        MatcherAssert.assertThat(user.getRoles(), hasItem("rolemo4"));
    }

    @Test
    public void testCustomAttributes() throws Exception {

        Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .build();

        LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().size(), is(16));
        Assert.assertFalse(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().containsKey("attr.ldap.userpassword"));

        settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 0)
            .build();

        user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        assertThat(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().size(), is(2));

        settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .putList(ConfigConstants.LDAP_CUSTOM_ATTR_WHITELIST, "*objectclass*", "entryParentId")
            .build();

        user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        assertThat(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().size(), is(2));

    }

    @Test
    public void testLdapAuthorizationNonDNRoles() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put("roles.g1.search", "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description, ou") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("nondnroles"), null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("nondnroles"));
        assertThat(user.getRoles().size(), is(5));
        Assert.assertTrue("Roles do not contain non-LDAP role 'kibanauser'", user.getRoles().contains("kibanauser"));
        Assert.assertTrue("Roles do not contain non-LDAP role 'humanresources'", user.getRoles().contains("humanresources"));
        Assert.assertTrue("Roles do not contain LDAP role 'dummyempty'", user.getRoles().contains("dummyempty"));
        Assert.assertTrue("Roles do not contain non-LDAP role 'role2'", user.getRoles().contains("role2"));
        Assert.assertTrue(
            "Roles do not contain non-LDAP role 'anotherrole' from second role name",
            user.getRoles().contains("anotherrole")
        );
    }

    @Test
    public void testChainedLdapAuthentication1() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("users.u2.search", "(uid={0})")
            .put("users.u2.base", "ou=people2,o=TEST")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testChainedLdapAuthentication2() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("users.u2.search", "(uid={0})")
            .put("users.u2.base", "ou=people2,o=TEST")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("presleye", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Elvis Presley,ou=people2,o=TEST"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testChainedLdapAuthenticationDuplicate() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_SEARCH_ALL_BASES, true)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put("users.u2.search", "(uid={0})")
            .put("users.u2.base", "ou=people2,o=TEST")
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        // Fails with OpenSearchSecurityException because two possible instances are
        // found
    }

    @Test
    public void testChainedLdapExists() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u2.search", "(uid={0})")
            .put("users.u2.base", "ou=people2,o=TEST")
            .build();

        final LDAPAuthenticationBackend lbe = new LDAPAuthenticationBackend(settings, null);
        Assert.assertTrue(lbe.impersonate(new User("jacksonm")).isPresent());
        Assert.assertTrue(lbe.impersonate(new User("presleye")).isPresent());
        Assert.assertFalse(lbe.impersonate(new User("doesnotexist")).isPresent());
    }

    @Test
    public void testChainedLdapAuthorization() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put("roles.g1.search", "(uniqueMember={0})")
            .put("roles.g2.base", "ou=groups2,o=TEST")
            .put("roles.g2.search", "(uniqueMember={0})")
            .build();

        final LdapUser ldapUser = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(ldapUser, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(3));

        Assert.assertTrue(user.getRoles().contains("ceo"));
        Assert.assertTrue(user.getRoles().contains("king"));
        Assert.assertTrue(user.getRoles().contains("role2"));

        assertThat(ldapUser.getUserEntry().getDn(), is(user.getName()));
    }

    @Test
    public void testCrossChainedLdapAuthorization() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put("users.u1.search", "(uid={0})")
            .put("users.u1.base", "ou=people2,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put("roles.g1.base", "ou=groups,o=TEST")
            .put("roles.g1.search", "(uniqueMember={0})")
            .put("roles.g2.base", "ou=groups2,o=TEST")
            .put("roles.g2.search", "(uniqueMember={0})")
            .build();

        final LdapUser ldapUser = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("mercuryf", "secret".getBytes(StandardCharsets.UTF_8))
        );

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(ldapUser, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Freddy Mercury,ou=people2,o=TEST"));
        assertThat(user.getRoles().size(), is(1));

        Assert.assertTrue(user.getRoles().contains("crossnested2"));
        // The user is NOT in crossnested1!
    }

    @AfterClass
    public static void tearDown() throws Exception {

        if (ldapServer != null) {
            ldapServer.stop();
        }

    }
}
