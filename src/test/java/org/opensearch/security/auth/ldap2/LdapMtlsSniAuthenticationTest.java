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

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.ldap.srv.EmbeddedLDAPServer;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Proves that SNI hostname is correctly propagated via ThreadLocal when connecting over LDAPS.
 *
 * The LDAP client connects to "localhost" with explicit hostname verification enabled.
 * BouncyCastle requires the hostname from ThreadLocal (set by HostnameAwareConnectionFactory
 * before JNDI resolves it to an IP) to verify the server certificate's SAN against "localhost".
 * Successful authentication proves SNI was correctly set — without it, BouncyCastle cannot
 * determine the expected hostname and hostname verification would fail.
 */
public class LdapMtlsSniAuthenticationTest {

    private static EmbeddedLDAPServer ldapServer;
    private static int ldapsPort;

    @BeforeClass
    public static void startLdapServer() throws Exception {
        ldapServer = new EmbeddedLDAPServer();
        ldapServer.applyLdif("base.ldif");
        ldapsPort = ldapServer.getLdapsPort();
    }

    @AfterClass
    public static void stopLdapServer() throws Exception {
        if (ldapServer != null) {
            ldapServer.stop();
        }
    }

    @Test
    public void authenticate_succeeds_provingSnIAndHostnameVerification() throws Exception {
        Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
            .put("users.u1.search", "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(ConfigConstants.LDAPS_VERIFY_HOSTNAMES, true)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, FileHelper.resolveStore("ldap/truststore").path())
            .put("path.home", ".")
            .build();

        User user = new LDAPAuthenticationBackend2(settings, null).authenticate(
            new AuthenticationContext(new AuthCredentials("jacksonm", "secret".getBytes()))
        );

        assertThat(user, is(notNullValue()));
        assertThat(user.getName(), is("cn=Michael Jackson,ou=people,o=TEST"));
    }
}
