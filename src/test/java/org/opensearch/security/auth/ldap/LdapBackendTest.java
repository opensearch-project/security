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

package org.opensearch.security.auth.ldap;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import org.hamcrest.MatcherAssert;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.ldap.backend.LDAPAuthenticationBackend;
import org.opensearch.security.auth.ldap.backend.LDAPAuthorizationBackend;
import org.opensearch.security.auth.ldap.srv.EmbeddedLDAPServer;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.auth.ldap.util.LdapHelper;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import org.ldaptive.Connection;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.ReturnAttributes;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

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
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationFakeLogin() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, true)
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(ctx("unknown", "unknown"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapInjection() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        String injectString = "*jack*";

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx(injectString, "secret"));
    }

    @Test
    public void testLdapAuthenticationBindDn() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_BIND_DN, "cn=Captain Spock,ou=people,o=TEST")
            .put(ConfigConstants.LDAP_PASSWORD, "spocksecret")
            .build();

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationWrongBindDn() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_BIND_DN, "cn=Captain Spock,ou=people,o=TEST")
            .put(ConfigConstants.LDAP_PASSWORD, "wrong")
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationBindFail() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "wrong"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationNoUser() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(ctx("UNKNOWN", "UNKNOWN"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationFail() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "xxxxx"));
    }

    @Test
    public void testLdapAuthenticationSSL() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .build();

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLPEMFile() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/root-ca.pem").toFile().getName()
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .put("path.conf", FileHelper.getAbsoluteFilePathFromClassPath("ldap/root-ca.pem").getParent())
            .build();
        User user = new LDAPAuthenticationBackend(settings, Paths.get("src/test/resources/ldap")).authenticate(ctx("jacksonm", "secret"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLPEMText() throws Exception {
        final Settings settingsFromFile = Settings.builder()
            .loadFromPath(Paths.get(FileHelper.getAbsoluteFilePathFromClassPath("ldap/test1.yml").toFile().getAbsolutePath()))
            .build();
        Settings settings = Settings.builder().put(settingsFromFile).putList("hosts", "localhost:" + ldapsPort).build();
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLSSLv3() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
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
            new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        } catch (Exception e) {
            assertThat(org.ldaptive.LdapException.class, is(e.getCause().getClass()));
            Assert.assertTrue(e.getCause().getMessage().contains("Unable to connec"));
        }

    }

    @Test
    public void testLdapAuthenticationSSLUnknowCipher() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
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
            new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        } catch (Exception e) {
            assertThat(org.ldaptive.LdapException.class, is(e.getCause().getClass()));
            Assert.assertTrue(e.getCause().getMessage().contains("Unable to connec"));
        }

    }

    @Test
    public void testLdapAuthenticationSpecialCipherProtocol() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
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

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));

    }

    @Test
    public void testLdapAuthenticationSSLNoKeystore() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .build();

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLFailPlain() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .build();

        try {
            new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        } catch (final Exception e) {
            assertThat(e.getCause().getClass(), is(org.ldaptive.LdapException.class));
        }
    }

    @Test
    public void testLdapExists() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        final LDAPAuthenticationBackend lbe = new LDAPAuthenticationBackend(settings, null);
        Assert.assertTrue(lbe.impersonate(new User("jacksonm")).isPresent());
        Assert.assertFalse(lbe.impersonate(new User("doesnotexist")).isPresent());
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
            // .put("plugins.security.authentication.authorization.ldap.userrolename",
            // "(uniqueMember={0})")
            .build();

        AuthenticationContext context = ctx("jacksonm", "secret");
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(context);

        assertThat(context.getContextData(LdapEntry.class).orElseThrow().getDn(), is(user.getName()));

        user = new LDAPAuthorizationBackend(settings, null).addRoles(user, context);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(2));
        MatcherAssert.assertThat(user.getRoles(), hasItem("ceo"));
    }

    @Test
    public void testLdapAuthenticationReturnAttributes() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .putList(ConfigConstants.LDAP_RETURN_ATTRIBUTES, "mail", "cn", "uid")
            .build();

        AuthenticationContext context = ctx("jacksonm", "secret");
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(context);

        final String[] attributes = context.getContextData(LdapEntry.class).orElseThrow().getAttributeNames();

        Assert.assertNotNull(user);
        assertThat(attributes.length, is(3));
        Assert.assertTrue(Arrays.asList(attributes).contains("mail"));
        Assert.assertTrue(Arrays.asList(attributes).contains("cn"));
        Assert.assertTrue(Arrays.asList(attributes).contains("uid"));
    }

    @Test
    public void testLdapAuthenticationReferral() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
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
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .build();

        AuthenticationContext context = ctx("ssign", "ssignsecret");
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(context);
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Special\\, Sign,ou=people,o=TEST"));
        User userWithRoles = new LDAPAuthorizationBackend(settings, null).addRoles(user, context);
        assertThat(userWithRoles.getName(), is("cn=Special\\, Sign,ou=people,o=TEST"));
        assertThat(userWithRoles.getRoles().size(), is(4));
        Assert.assertTrue(userWithRoles.getRoles().toString().contains("ceo"));
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

        AuthenticationContext context = ctx("Michael Jackson", "secret");
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(context);
        User userWithRoles = new LDAPAuthorizationBackend(settings, null).addRoles(user, context);

        Assert.assertNotNull(user);
        assertThat(context.getContextData(LdapEntry.class).orElseThrow().getDn(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(userWithRoles.getRoles().size(), is(2));
        MatcherAssert.assertThat(userWithRoles.getRoles(), hasItem("ceo"));
        assertThat(context.getContextData(LdapEntry.class).orElseThrow().getDn(), is(user.getName()));
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

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("jacksonm"), ctx("jacksonm", "secret"));

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
        assertThat(user.getRoles().size(), is(2));
        MatcherAssert.assertThat(user.getRoles(), hasItem("ceo"));
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

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("jacksonm"), ctx("jacksonm", "secret"));

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
        assertThat(user.getRoles().size(), is(2));
        MatcherAssert.assertThat(user.getRoles(), hasItem("ceo-ceo"));
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

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), ctx("spock", "secret"));

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));
        MatcherAssert.assertThat(user.getRoles(), hasItem("nested1"));
    }

    @Test
    public void testLdapNestedRoleFiltering() {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .putList(ConfigConstants.LDAP_AUTHZ_EXCLUDE_ROLES, List.of("nested1", "nested2"))
            .build();

        User user = new User("spock");
        user = new LDAPAuthorizationBackend(settings, null).addRoles(user, ctx("spock", "secret"));

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(2));
        // filtered out
        MatcherAssert.assertThat(user.getRoles(), not(hasItem("nested1")));
        MatcherAssert.assertThat(user.getRoles(), not(hasItem("nested2")));
        MatcherAssert.assertThat(user.getRoles(), hasItem("role2"));
        MatcherAssert.assertThat(user.getRoles(), hasItem("ceo"));
    }

    @Test
    public void testLdapNestedRoleFilteringWithExcludedRolesWildcard() {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .putList(ConfigConstants.LDAP_AUTHZ_EXCLUDE_ROLES, List.of("nested*"))
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), ctx("spock", "secret"));

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(2));
        // filtered out
        MatcherAssert.assertThat(user.getRoles(), not(hasItem("nested1")));
        MatcherAssert.assertThat(user.getRoles(), not(hasItem("nested2")));
        MatcherAssert.assertThat(user.getRoles(), hasItem("role2"));
        MatcherAssert.assertThat(user.getRoles(), hasItem("ceo"));
    }

    @Test
    public void testLdapdRoleFiltering() {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .putList(ConfigConstants.LDAP_AUTHZ_EXCLUDE_ROLES, List.of("ceo", "role1", "role2"))
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), ctx("spock", "secret"));

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(2));
        MatcherAssert.assertThat(user.getRoles(), hasItem("nested1"));
        MatcherAssert.assertThat(user.getRoles(), hasItem("nested2"));
        // filtered out
        MatcherAssert.assertThat(user.getRoles(), not(hasItem("role2")));
        MatcherAssert.assertThat(user.getRoles(), not(hasItem("ceo")));
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

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), ctx("spock", "secret"));

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
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "dn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), ctx("spock", "secret"));

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));
        MatcherAssert.assertThat(user.getRoles(), hasItem("cn=nested1,ou=groups,o=TEST"));
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

        AuthenticationContext context = ctx("jacksonm", "secret");
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(context);
        user = new LDAPAuthorizationBackend(settings, null).addRoles(user, context);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
        assertThat(user.getRoles().size(), is(2));
        MatcherAssert.assertThat(user.getRoles(), hasItem("cn=ceo,ou=groups,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationUserNameAttribute() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .build();

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
    }

    @Test
    public void testLdapAuthenticationStartTLS() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_START_TLS, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .build();

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
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

        AuthenticationContext context = ctx("jacksonm", "secret");
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(context);
        user = new LDAPAuthorizationBackend(settings, null).addRoles(user, context);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(0));
        assertThat(context.getContextData(LdapEntry.class).orElseThrow().getDn(), is(user.getName()));
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

        AuthenticationContext context = ctx("jacksonm", "secret");
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(context);
        user = new LDAPAuthorizationBackend(settings, null).addRoles(user, context);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(0));
        assertThat(context.getContextData(LdapEntry.class).orElseThrow().getDn(), is(user.getName()));
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

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), ctx("spock", "secret"));

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

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), ctx("spock", "secret"));

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

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), ctx("spock", "secret"));

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));

    }

    @Test
    public void testLdapAuthorizationNestedAttrFilterAllEqualsNestedFalse() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false) // -> same like
                                                                         // putList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER, "*")
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
            .build();

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), ctx("spock", "secret"));

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));

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

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spock"), ctx("spock", "secret"));

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
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().size(), is(16));
        Assert.assertFalse(
            user.getCustomAttributesMap().toString(),
            user.getCustomAttributesMap().keySet().contains("attr.ldap.userpassword")
        );

        settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 0)
            .build();

        user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));

        assertThat(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().size(), is(2));

        settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .putList(ConfigConstants.LDAP_CUSTOM_ATTR_WHITELIST, "*objectclass*", "entryParentId")
            .build();

        user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("jacksonm", "secret"));

        assertThat(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().size(), is(2));

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

        User user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("nondnroles"), ctx("nondnroles", "secret"));

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

        AuthenticationContext context = ctx("spec186", "spec186");
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(context);
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"));
        assertThat(
            context.getContextData(LdapEntry.class).orElseThrow().getAttribute("cn").getStringValue(),
            is("AA BB/CC (DD) my, company end=with=whitespace ")
        );
        user = new LDAPAuthorizationBackend(settings, null).addRoles(user, context);

        assertThat(user.getRoles().size(), is(3));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLEx(186n) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186nn) consists of\\, special="));

        user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spec186"), context);
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLEx(186n) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186nn) consists of\\, special="));

        user = new LDAPAuthorizationBackend(settings, null).addRoles(
            new User("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"),
            context
        );
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLEx(186n) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186nn) consists of\\, special="));

        user = new LDAPAuthorizationBackend(settings, null).addRoles(
            new User("CN=AA BB\\/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"),
            context
        );
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

        AuthenticationContext context = ctx("spec186", "spec186");
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(context);
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"));
        assertThat(
            context.getContextData(LdapEntry.class).orElseThrow().getAttribute("cn").getStringValue(),
            is("AA BB/CC (DD) my, company end=with=whitespace ")
        );
        user = new LDAPAuthorizationBackend(settings, null).addRoles(user, context);

        assertThat(user.getRoles().size(), is(3));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));

        user = new LDAPAuthorizationBackend(settings, null).addRoles(new User("spec186"), context);
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));

        user = new LDAPAuthorizationBackend(settings, null).addRoles(
            new User("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"),
            context
        );
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));

        user = new LDAPAuthorizationBackend(settings, null).addRoles(
            new User("CN=AA BB\\/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"),
            context
        );
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));
    }

    @Test
    public void testOperationalAttributes() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        AuthenticationContext context = ctx("jacksonm", "secret");
        User user = new LDAPAuthenticationBackend(settings, null).authenticate(context);
        Assert.assertNotNull(user);
        LdapAttribute operationAttribute = context.getContextData(LdapEntry.class).orElseThrow().getAttribute("entryUUID");
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

        User user = new LDAPAuthenticationBackend(settings, null).authenticate(ctx("multi", "multi"));
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=cabc,ou=people,o=TEST"));
    }

    @AfterClass
    public static void tearDown() throws Exception {

        if (ldapServer != null) {
            ldapServer.stop();
        }

    }

    static AuthenticationContext ctx(String userName, String password) {
        return new AuthenticationContext(new AuthCredentials(userName, password.getBytes(StandardCharsets.UTF_8)));
    }
}
