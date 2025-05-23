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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.TreeSet;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.hamcrest.MatcherAssert;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.ldap.backend.LDAPAuthenticationBackend;
import org.opensearch.security.auth.ldap.backend.LDAPAuthorizationBackend;
import org.opensearch.security.auth.ldap.srv.EmbeddedLDAPServer;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.auth.ldap.util.LdapHelper;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import com.amazon.dlic.auth.ldap.LdapUser;
import org.ldaptive.Connection;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.ReturnAttributes;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;

@RunWith(Parameterized.class)
public class LdapBackendTestOldStyleConfig2 {

    private static final WildcardMatcher EXCEPTION_MATCHER = WildcardMatcher.from("*unsupported*ciphersuite*aaa*");

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

    @Parameters
    public static Object[] parameters() {
        return new Object[] { Boolean.FALSE, Boolean.TRUE };
    }

    protected Settings.Builder createBaseSettings() {
        if (poolEnabled) {
            return Settings.builder().put(ConfigConstants.LDAP_POOL_ENABLED, true);
        } else {
            return Settings.builder();
        }
    }

    @Parameter
    public boolean poolEnabled;

    @Test
    public void testLdapAuthentication() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationPooled() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_POOL_ENABLED, true)
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationFakeLogin() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, true)
            .build();

        new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("unknown", "unknown".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapInjection() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        String injectString = "*jack*";

        @SuppressWarnings("unused")
        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials(injectString, "secret".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test
    public void testLdapAuthenticationBindDn() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_BIND_DN, "cn=Captain Spock,ou=people,o=TEST")
            .put(ConfigConstants.LDAP_PASSWORD, "spocksecret")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationWrongBindDn() throws Exception {
        try {
            final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_BIND_DN, "cn=Captain Spock,ou=people,o=TEST")
                .put(ConfigConstants.LDAP_PASSWORD, "wrong")
                .build();

            new LDAPAuthenticationBackend2(settings, null).authenticate(
                new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
            );
            Assert.fail("Expected exception");
        } catch (Exception e) {
            Assert.assertTrue(ExceptionUtils.getStackTrace(e), ExceptionUtils.getStackTrace(e).contains("password was incorrect"));
        }
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationBindFail() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "wrong".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationNoUser() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("UNKNOWN", "UNKNOWN".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationFail() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "xxxxx".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testLdapAuthenticationFailPooled() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_POOL_ENABLED, true)
            .build();

        new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "xxxxx".getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test
    public void testLdapAuthenticationSSL() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLPooled() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(ConfigConstants.LDAP_POOL_ENABLED, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLPEMFile() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
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
        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, Paths.get("src/test/resources/ldap")).authenticate(
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
        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLSSLv3() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
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
            new LDAPAuthenticationBackend2(settings, null).authenticate(
                new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
            );
            Assert.fail("Expected Exception");
        } catch (Exception e) {
            assertThat(e.getCause().getClass(), is(org.ldaptive.provider.ConnectionException.class));
            Assert.assertTrue(ExceptionUtils.getStackTrace(e).contains("No appropriate protocol"));
        }

    }

    @Test
    public void testLdapAuthenticationSSLUnknowCipher() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
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
            new LDAPAuthenticationBackend2(settings, null).authenticate(
                new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
            );
            Assert.fail("Expected Exception");
        } catch (Exception e) {
            assertThat(e.getCause().getClass().toString(), org.ldaptive.provider.ConnectionException.class, is(e.getCause().getClass()));
            Assert.assertTrue(ExceptionUtils.getStackTrace(e), EXCEPTION_MATCHER.test(ExceptionUtils.getStackTrace(e).toLowerCase()));
        }

    }

    @Test
    public void testLdapAuthenticationSpecialCipherProtocol() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
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

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));

    }

    @Test
    public void testLdapAuthenticationSSLNoKeystore() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationSSLFailPlain() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .build();

        try {
            new LDAPAuthenticationBackend2(settings, new File("").toPath()).authenticate(
                new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
            );
            Assert.fail("Expected exception");
        } catch (final Exception e) {
            assertThat(e.getCause().getClass(), is(IllegalStateException.class));
        }
    }

    @Test
    public void testLdapExists() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        final LDAPAuthenticationBackend2 lbe = new LDAPAuthenticationBackend2(settings, null);
        Assert.assertTrue(lbe.exists(new User("jacksonm")));
        Assert.assertFalse(lbe.exists(new User("doesnotexist")));
    }

    @Test
    public void testLdapAuthorization() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            // .put("plugins.security.authentication.authorization.ldap.userrolename",
            // "(uniqueMember={0})")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(2));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(0), is("ceo"));
        assertThat(user.getUserEntry().getDn(), is(user.getName()));
    }

    @Test
    public void testLdapAuthorizationPooled() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_POOL_ENABLED, true)
            // .put("plugins.security.authentication.authorization.ldap.userrolename",
            // "(uniqueMember={0})")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(2));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(0), is("ceo"));
        assertThat(user.getUserEntry().getDn(), is(user.getName()));
    }

    @Test
    public void testLdapAuthenticationReferral() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        final Connection con = new LDAPConnectionFactoryFactory(settings, null).createBasicConnectionFactory().getConnection();
        try {
            con.open();
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

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("ssign", "ssignsecret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Special\\, Sign,ou=people,o=TEST"));
        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);
        assertThat(user.getName(), is("cn=Special\\, Sign,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(4));
        Assert.assertTrue(user.getRoles().toString().contains("ceo"));
    }

    @Test
    public void testLdapAuthorizationRoleSearchUsername() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(cn={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember=cn={1},ou=people,o=TEST)")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("Michael Jackson", "secret".getBytes(StandardCharsets.UTF_8))
        );

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        assertThat(user.getOriginalUsername(), is("Michael Jackson"));
        assertThat(user.getUserEntry().getDn(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(2));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(0), is("ceo"));
        assertThat(user.getUserEntry().getDn(), is(user.getName()));
    }

    @Test
    public void testLdapAuthorizationOnly() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .build();

        final User user = new User("jacksonm");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
        assertThat(user.getRoles().size(), is(2));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(0), is("ceo"));
    }

    @Test
    public void testLdapAuthorizationNested() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
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
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(1), is("nested1"));
    }

    @Test
    public void testLdapAuthorizationNestedFilter() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
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
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(2));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(0), is("ceo"));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(1), is("nested2"));
    }

    @Test
    public void testLdapAuthorizationDnNested() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
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
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(1), is("cn=nested1,ou=groups,o=TEST"));
    }

    @Test
    public void testLdapAuthorizationDn() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "dn")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "UID")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false)
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .build();

        final User user = new LDAPAuthenticationBackend2(settings, null).authenticate(new AuthCredentials("jacksonm", "secret".getBytes()));

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
        assertThat(user.getRoles().size(), is(2));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(0), is("cn=ceo,ou=groups,o=TEST"));
    }

    @Test
    public void testLdapAuthenticationUserNameAttribute() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
    }

    @Test
    public void testLdapAuthenticationStartTLS() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_START_TLS, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ldap/truststore.jks")
            )
            .put("verify_hostnames", false)
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }

    @Test
    public void testLdapAuthorizationSkipUsers() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .putList(ConfigConstants.LDAP_AUTHZ_SKIP_USERS, "cn=Michael Jackson,ou*people,o=TEST")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getRoles().size(), is(0));
        assertThat(user.getUserEntry().getDn(), is(user.getName()));
    }

    @Test
    public void testLdapAuthorizationNestedAttr() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
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
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(8));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(4), is("nested3"));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(7), is("rolemo4"));
    }

    @Test
    public void testLdapAuthorizationNestedAttrFilter() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
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
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(6));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(4), is("role2"));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(2), is("nested1"));

    }

    @Test
    public void testLdapAuthorizationNestedAttrFilterAll() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
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
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));

    }

    @Test
    public void testLdapAuthorizationNestedAttrFilterAllEqualsNestedFalse() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
            .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
            .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false) // -> same like
                                                                         // putList(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER,
                                                                         // "*")
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
            .put(ConfigConstants.LDAP_AUTHZ_USERROLENAME, "description") // no memberOf OID
            .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true)
            .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(4));

    }

    @Test
    public void testLdapAuthorizationNestedAttrNoRoleSearch() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
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
        assertThat(user.getName(), is("spock"));
        assertThat(user.getRoles().size(), is(3));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(1), is("nested3"));
        assertThat(new ArrayList<>(new TreeSet<>(user.getRoles())).get(2), is("rolemo4"));
    }

    @Test
    public void testCustomAttributes() throws Exception {

        Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();

        LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
        assertThat(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().size(), is(16));
        Assert.assertFalse(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().containsKey("attr.ldap.userpassword"));

        settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 0)
            .build();

        user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        assertThat(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().size(), is(2));

        settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + ldapPort)
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .putList(ConfigConstants.LDAP_CUSTOM_ATTR_WHITELIST, "*objectclass*", "entryParentId")
            .build();

        user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );

        assertThat(user.getCustomAttributesMap().toString(), user.getCustomAttributesMap().size(), is(2));

    }

    @Test
    public void testLdapAuthorizationNonDNRoles() throws Exception {

        final Settings settings = createBaseSettings().putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapPort)
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

        new LDAPAuthorizationBackend2(settings, null).fillRoles(user, null);

        Assert.assertNotNull(user);
        assertThat(user.getName(), is("jacksonm"));
        assertThat(user.getRoles().size(), is(2));
        MatcherAssert.assertThat(user.getRoles(), hasItem("ceo-ceo"));
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

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("spec186", "spec186".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"));
        assertThat(user.getUserEntry().getAttribute("cn").getStringValue(), is("AA BB/CC (DD) my, company end=with=whitespace "));
        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        assertThat(user.getRoles().size(), is(3));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLEx(186n) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186nn) consists of\\, special="));

        new LDAPAuthorizationBackend(settings, null).fillRoles(new User("spec186"), null);
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLEx(186n) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186nn) consists of\\, special="));

        new LDAPAuthorizationBackend(settings, null).fillRoles(
            new User("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"),
            null
        );
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLEx(186n) consists of\\, special="));
        Assert.assertTrue(user.getRoles().toString().contains("ROLE/(186nn) consists of\\, special="));

        new LDAPAuthorizationBackend(settings, null).fillRoles(
            new User("CN=AA BB\\/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"),
            null
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

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("spec186", "spec186".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        assertThat(user.getName(), is("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"));
        assertThat(user.getUserEntry().getAttribute("cn").getStringValue(), is("AA BB/CC (DD) my, company end=with=whitespace "));
        new LDAPAuthorizationBackend(settings, null).fillRoles(user, null);

        assertThat(user.getRoles().size(), is(3));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));

        new LDAPAuthorizationBackend(settings, null).fillRoles(new User("spec186"), null);
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));

        new LDAPAuthorizationBackend(settings, null).fillRoles(
            new User("CN=AA BB/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"),
            null
        );
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186n) consists of\\, special\\=chars\\ "));
        Assert.assertTrue(user.getRoles().toString().contains("cn=ROLE/(186nn) consists of\\, special\\=chars\\ "));

        new LDAPAuthorizationBackend(settings, null).fillRoles(
            new User("CN=AA BB\\/CC (DD) my\\, company end\\=with\\=whitespace\\ ,ou=people,o=TEST"),
            null
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

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        LdapAttribute operationAttribute = user.getUserEntry().getAttribute("entryUUID");
        Assert.assertNotNull(operationAttribute);
        Assert.assertNotNull(operationAttribute.getStringValue());
        Assert.assertTrue(operationAttribute.getStringValue().length() > 10);
        Assert.assertTrue(operationAttribute.getStringValue().split("-").length == 5);
    }

    @AfterClass
    public static void tearDown() throws Exception {

        if (ldapServer != null) {
            ldapServer.stop();
        }

    }

}
