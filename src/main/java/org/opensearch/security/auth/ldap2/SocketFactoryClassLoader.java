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

import org.ldaptive.ssl.ThreadLocalTLSSocketFactory;

/**
 * Classloader that resolves the JNDI LDAP socket-factory classes by name.
 *
 * <p>On Java 9+ the module system means JNDI's {@code com.sun.jndi.ldap.Connection.getSocketFactory}
 * loads the class named by {@code java.naming.ldap.factory.socket} through the {@code java.naming}
 * module loader, which cannot see application/plugin classes on the classpath. Installing this as the
 * thread-context classloader lets JNDI resolve {@link SNISettingTLSSocketFactory} (and ldaptive's
 * {@link ThreadLocalTLSSocketFactory}) by name; everything else delegates to the parent loader.
 */
public final class SocketFactoryClassLoader extends ClassLoader {

    // Matched as string literals so a lookup for any other class never touches the factory class literals.
    static final String SNI_SETTING_TLS_SOCKET_FACTORY = "org.opensearch.security.auth.ldap2.SNISettingTLSSocketFactory";
    static final String THREAD_LOCAL_TLS_SOCKET_FACTORY = "org.ldaptive.ssl.ThreadLocalTLSSocketFactory";

    public SocketFactoryClassLoader() {
        super();
    }

    public SocketFactoryClassLoader(ClassLoader parent) {
        super(parent);
    }

    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        return switch (name) {
            case SNI_SETTING_TLS_SOCKET_FACTORY -> SNISettingTLSSocketFactory.class;
            case THREAD_LOCAL_TLS_SOCKET_FACTORY -> ThreadLocalTLSSocketFactory.class;
            default -> super.loadClass(name);
        };
    }
}
