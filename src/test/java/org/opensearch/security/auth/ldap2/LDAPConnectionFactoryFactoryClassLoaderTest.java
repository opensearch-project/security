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

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;

import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.provider.Provider;
import org.ldaptive.provider.jndi.JndiProviderConfig;
import org.ldaptive.ssl.ThreadLocalTLSSocketFactory;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;

public class LDAPConnectionFactoryFactoryClassLoaderTest {

    private static final String SNI_FACTORY = "org.opensearch.security.auth.ldap2.SNISettingTLSSocketFactory";

    /** Builds a real factory and returns the classloader ldap2 sets on the JNDI provider config. */
    private static ClassLoader factoryProvidedClassLoader() throws Exception {
        Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:636")
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, FileHelper.resolveStore("ldap/truststore").path())
            .put("path.home", ".")
            .build();

        DefaultConnectionFactory connectionFactory = new LDAPConnectionFactoryFactory(settings, null).createBasicConnectionFactory();

        @SuppressWarnings("unchecked")
        Provider<JndiProviderConfig> provider = (Provider<JndiProviderConfig>) connectionFactory.getProvider();
        return provider.getProviderConfig().getClassLoader();
    }

    @Test
    public void providerConfig_carriesClassLoaderThatResolvesSniSocketFactory() throws Exception {
        ClassLoader factoryClassLoader = factoryProvidedClassLoader();
        assertThat(factoryClassLoader.loadClass(SNI_FACTORY), is(sameInstance(SNISettingTLSSocketFactory.class)));
    }

    @Test
    public void providerConfig_classLoaderResolvesThreadLocalTlsSocketFactory() throws Exception {
        ClassLoader factoryClassLoader = factoryProvidedClassLoader();
        assertThat(
            factoryClassLoader.loadClass(ThreadLocalTLSSocketFactory.class.getName()),
            is(sameInstance(ThreadLocalTLSSocketFactory.class))
        );
    }

    @Test
    public void providerConfig_classLoaderDelegatesUnknownClassesToParent() throws Exception {
        ClassLoader factoryClassLoader = factoryProvidedClassLoader();
        assertThrows(ClassNotFoundException.class, () -> factoryClassLoader.loadClass("com.example.DoesNotExist"));
    }

    @Test
    public void noArgConstructor_resolvesSniSocketFactory() throws Exception {
        ClassLoader loader = new SocketFactoryClassLoader();
        assertThat(loader.loadClass(SNI_FACTORY), is(sameInstance(SNISettingTLSSocketFactory.class)));
    }
}
