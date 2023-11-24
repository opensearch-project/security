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

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.user.AuthCredentials;

import com.amazon.dlic.auth.ldap.backend.LDAPAuthenticationBackend;
import com.amazon.dlic.auth.ldap.util.ConfigConstants;

@Ignore
public class LdapBackendTestClientCert {

    static {
        System.setProperty("security.display_lic_none", "true");
    }

    @Test
    public void testNoAuth() throws Exception {

        // no auth

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:636")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/truststore.jks"
            )
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .put("path.home", ".")
            .build();

        LdapUser user;
        try {
            user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
                new AuthCredentials("ldap_hr_employee", "ldap_hr_employee".getBytes(StandardCharsets.UTF_8))
            );
            Assert.fail();
        } catch (Exception e) {
            Assert.assertTrue(
                ExceptionUtils.getRootCause(e).getMessage(),
                ExceptionUtils.getRootCause(e).getMessage().contains("authentication required")
            );
        }
    }

    @Test
    public void testNoAuthX() throws Exception {

        // no auth

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "kdc.dummy.com:636")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/truststore.jks"
            )
            .put(ConfigConstants.LDAPS_VERIFY_HOSTNAMES, false)
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .put("path.home", ".")
            .build();

        LdapUser user;
        try {
            user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
                new AuthCredentials("ldap_hr_employee", "ldap_hr_employee".getBytes(StandardCharsets.UTF_8))
            );
            Assert.fail();
        } catch (Exception e) {
            Assert.assertTrue(
                ExceptionUtils.getRootCause(e).getMessage(),
                ExceptionUtils.getRootCause(e).getMessage().contains("authentication required")
            );
        }
    }

    @Test
    public void testNoAuthY() throws Exception {

        // no auth

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "kdc.dummy.com:636")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/wrong/truststore.jks"
            )
            .put(ConfigConstants.LDAPS_VERIFY_HOSTNAMES, false)
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .put("path.home", ".")
            .build();

        LdapUser user;
        try {
            user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
                new AuthCredentials("ldap_hr_employee", "ldap_hr_employee".getBytes(StandardCharsets.UTF_8))
            );
            Assert.fail();
        } catch (Exception e) {
            Assert.assertTrue(
                ExceptionUtils.getRootCause(e).getMessage(),
                ExceptionUtils.getRootCause(e).getMessage().contains("Unable to connect to any")
            );
        }
    }

    @Test
    public void testBindDnAuthLocalhost() throws Exception {

        // bin dn auth

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:636")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/truststore.jks"
            )
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .put(ConfigConstants.LDAP_BIND_DN, "cn=ldapbinder,ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_PASSWORD, "ldapbinder")
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("ldap_hr_employee", "ldap_hr_employee".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        Assert.assertEquals("ldap_hr_employee", user.getName());
    }

    @Test
    public void testLdapSslAuth() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:636")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                "plugins.security.ssl.transport.keystore_filepath",
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/spock-keystore.jks"
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/truststore.jks"
            )
            .put(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH, true)
            .put(ConfigConstants.LDAPS_JKS_CERT_ALIAS, "spock")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("ldap_hr_employee", "ldap_hr_employee".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        Assert.assertEquals("ldap_hr_employee", user.getName());
    }

    @Test
    public void testLdapSslAuthPem() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:636")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH,
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/ca/root-ca.pem"
            )
            .put(
                ConfigConstants.LDAPS_PEMCERT_FILEPATH,
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/spock.crtfull.pem"
            )
            .put(ConfigConstants.LDAPS_PEMKEY_FILEPATH, "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/spock.key.pem")
            // .put(ConfigConstants.LDAPS_PEMKEY_PASSWORD, "changeit")
            .put(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH, true)
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .put("path.home", ".")
            // .put(ConfigConstants.LDAP_BIND_DN, "cn=ldapbinder,ou=people,dc=example,dc=com")
            // .put(ConfigConstants.LDAP_PASSWORD, "ldapbinder")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("ldap_hr_employee", "ldap_hr_employee".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        Assert.assertEquals("ldap_hr_employee", user.getName());
    }

    @Test
    public void testLdapSslAuthNo() throws Exception {

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:636")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(
                "plugins.security.ssl.transport.keystore_filepath",
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/kirk-keystore.jks"
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/truststore.jks"
            )
            .put(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH, true)
            .put(ConfigConstants.LDAPS_JKS_CERT_ALIAS, "kirk")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("ldap_hr_employee", "ldap_hr_employee".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        Assert.assertEquals("ldap_hr_employee", user.getName());
    }

    public void testLdapAuthenticationSSL() throws Exception {

        // startLDAPServer();

        final Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "kdc.dummy.com:636")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            // .put("plugins.security.ssl.transport.keystore_filepath",
            // "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/cn=ldapbinder,ou=people,dc=example,dc=com-keystore.jks")
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                "/Users/temp/opendistro_security_integration_tests/ldap/ssl-root-ca/truststore.jks"
            )
            // .put("verify_hostnames", false)
            // .put(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH, true)
            // .put(ConfigConstants.LDAPS_JKS_CERT_ALIAS, "cn=ldapbinder,ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            // .put(ConfigConstants.LDAP_BIND_DN, "cn=ldapbinder,ou=people,dc=example,dc=com")
            // .put(ConfigConstants.LDAP_PASSWORD, "ldapbinder")

            // .putList(ConfigConstants.LDAPS_ENABLED_SSL_CIPHERS, "TLS_RSA_WITH_AES_128_CBC_SHA")
            // .putList(ConfigConstants.LDAPS_ENABLED_SSL_PROTOCOLS, "TLSv1")
            // TLS_RSA_AES_128_CBC_SHA1
            .put("path.home", ".")
            .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings, null).authenticate(
            new AuthCredentials("ldap_hr_employee", "ldap_hr_employee".getBytes(StandardCharsets.UTF_8))
        );
        Assert.assertNotNull(user);
        Assert.assertEquals("ldap_hr_employee", user.getName());
    }

    public static File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        File file = null;
        final URL fileUrl = LdapBackendTestClientCert.class.getClassLoader().getResource(fileNameFromClasspath);
        if (fileUrl != null) {
            try {
                file = new File(URLDecoder.decode(fileUrl.getFile(), "UTF-8"));
            } catch (final UnsupportedEncodingException e) {
                return null;
            }

            if (file.exists() && file.canRead()) {
                return file;
            } else {
                System.err.println("Cannot read from {}, maybe the file does not exists? " + file.getAbsolutePath());
            }

        } else {
            System.err.println("Failed to load " + fileNameFromClasspath);
        }
        return null;
    }
}
