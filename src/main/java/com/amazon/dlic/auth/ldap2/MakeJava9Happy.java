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

package com.amazon.dlic.auth.ldap2;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.opensearch.SpecialPermission;

import io.netty.util.internal.PlatformDependent;
import org.ldaptive.ssl.ThreadLocalTLSSocketFactory;

public class MakeJava9Happy {

    private static ClassLoader classLoader;
    private static boolean isJava9OrHigher = PlatformDependent.javaVersion() >= 9;;

    @SuppressWarnings("removal")
    static ClassLoader getClassLoader() {
        if (!isJava9OrHigher) {
            return null;
        }

        if (classLoader == null) {
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            try {
                return AccessController.doPrivileged(new PrivilegedExceptionAction<ClassLoader>() {
                    @Override
                    public ClassLoader run() throws Exception {
                        return new Java9CL();
                    }
                });
            } catch (PrivilegedActionException e) {
                if (e.getException() instanceof RuntimeException) {
                    throw (RuntimeException) e.getException();
                } else {
                    throw new RuntimeException(e);
                }
            }
        }

        return classLoader;
    }

    @SuppressWarnings("rawtypes")
    private final static Class threadLocalTLSSocketFactoryClass = ThreadLocalTLSSocketFactory.class;

    private final static class Java9CL extends ClassLoader {

        public Java9CL() {
            super();
        }

        @SuppressWarnings("unused")
        public Java9CL(ClassLoader parent) {
            super(parent);
        }

        @SuppressWarnings({ "rawtypes", "unchecked" })
        @Override
        public Class loadClass(String name) throws ClassNotFoundException {

            if (!name.equalsIgnoreCase("org.ldaptive.ssl.ThreadLocalTLSSocketFactory")) {
                return super.loadClass(name);
            }

            return threadLocalTLSSocketFactoryClass;
        }
    }
}
