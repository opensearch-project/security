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

import java.net.InetAddress;
import java.net.ServerSocket;

import com.carrotsearch.randomizedtesting.rules.SystemPropertiesRestoreRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.ldap.backend.LDAPAuthorizationBackend;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.auth.ldap2.LDAPConnectionFactoryFactory;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

/**
 * {@code verify_hostnames: false} must not set the JVM-wide {@code com.sun.jndi.ldap.object.disableEndpointIdentification}
 * property: it would turn off JNDI's hostname check for every LDAPS connection in the JVM, including auth domains with
 * {@code verify_hostnames: true}.
 */
public class LdapEndpointIdentificationTest {

    @Rule
    public final SystemPropertiesRestoreRule restoreSystemProperties = new SystemPropertiesRestoreRule();

    @Before
    public void clearProperty() {
        System.clearProperty(ConfigConstants.LDAPS_DISABLE_ENDPOINT_IDENTIFICATION_PROPERTY);
    }

    @Test
    public void ldap_verifyHostnamesFalse_doesNotDisableEndpointIdentification() throws Exception {
        Settings settings = settingsWithoutHostnameVerification(closedPort());

        // the connection itself fails, but the TLS configuration (where the property used to be set) is built first
        assertThrows(Exception.class, () -> LDAPAuthorizationBackend.getConnection(settings, null));

        assertNull(System.getProperty(ConfigConstants.LDAPS_DISABLE_ENDPOINT_IDENTIFICATION_PROPERTY));
    }

    @Test
    public void ldap2_verifyHostnamesFalse_doesNotDisableEndpointIdentification() throws Exception {
        Settings settings = settingsWithoutHostnameVerification(closedPort());

        new LDAPConnectionFactoryFactory(settings, null).createBasicConnectionFactory();

        assertNull(System.getProperty(ConfigConstants.LDAPS_DISABLE_ENDPOINT_IDENTIFICATION_PROPERTY));
    }

    private static Settings settingsWithoutHostnameVerification(int port) {
        return Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + port)
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(ConfigConstants.LDAPS_VERIFY_HOSTNAMES, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, FileHelper.resolveStore("ldap/truststore").path())
            .put("path.home", ".")
            .build();
    }

    private static int closedPort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }
}
