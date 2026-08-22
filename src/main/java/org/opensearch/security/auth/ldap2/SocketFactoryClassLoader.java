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

    public SocketFactoryClassLoader() {
        super();
    }

    public SocketFactoryClassLoader(ClassLoader parent) {
        super(parent);
    }

    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        if (SNISettingTLSSocketFactory.class.getName().equals(name)) {
            return SNISettingTLSSocketFactory.class;
        }
        if (ThreadLocalTLSSocketFactory.class.getName().equalsIgnoreCase(name)) {
            return ThreadLocalTLSSocketFactory.class;
        }
        return super.loadClass(name);
    }
}
