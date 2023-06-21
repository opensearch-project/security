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

package org.opensearch.security.support;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.opensearch.SpecialPermission;

public class ReflectiveAttributeAccessors {
    public static <O> Function<O, Object> objectAttr(String name) {
        return new ReflectiveAttributeGetter<O, Object>(name, Object.class);
    }

    public static <O, R> Function<O, R> objectAttr(String name, Class<R> type) {
        return new ReflectiveAttributeGetter<O, R>(name, type);
    }

    public static <O, R> Function<O, R> protectedObjectAttr(String name, Class<R> type) {
        return new ProtectedReflectiveAttributeGetter<O, R>(name, type);
    }

    public static <O, V> BiFunction<O, V, Void> setObjectAttr(String name, Class<V> type) {
        return new ReflectiveAttributeSetter<O, V>(name, type);
    }

    static class ReflectiveAttributeGetter<O, R> implements Function<O, R> {
        private final String attribute;
        private final String methodName;
        private final Class<R> type;

        ReflectiveAttributeGetter(String attribute, Class<R> type) {
            this.attribute = attribute;
            this.methodName = "get" + attribute.substring(0, 1).toUpperCase() + attribute.substring(1);
            this.type = type;
        }

        @SuppressWarnings("removal")
        @Override
        public R apply(O object) {
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            return AccessController.doPrivileged((PrivilegedAction<R>) () -> {
                if (object == null) {
                    return null;
                }

                try {
                    Method method = object.getClass().getMethod(methodName);
                    Object value = method.invoke(object);

                    return type.cast(value);

                } catch (Exception e) {
                    throw new RuntimeException("Error while accessing " + attribute + " in " + object, e);
                }
            });
        }
    }

    static class ProtectedReflectiveAttributeGetter<O, R> implements Function<O, R> {
        private final String attribute;
        private final String methodName;
        private final Class<R> type;

        ProtectedReflectiveAttributeGetter(String attribute, Class<R> type) {
            this.attribute = attribute;
            this.methodName = "get" + attribute.substring(0, 1).toUpperCase() + attribute.substring(1);
            this.type = type;
        }

        @SuppressWarnings("removal")
        @Override
        public R apply(O object) {
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            return AccessController.doPrivileged((PrivilegedAction<R>) () -> {
                if (object == null) {
                    return null;
                }

                try {
                    Method method = object.getClass().getDeclaredMethod(methodName);
                    method.setAccessible(true);
                    Object value = method.invoke(object);

                    return type.cast(value);

                } catch (Exception e) {
                    throw new RuntimeException("Error while accessing " + attribute + " in " + object, e);
                }
            });
        }
    }

    static class ReflectiveAttributeSetter<O, R> implements BiFunction<O, R, Void> {
        private final String attribute;
        private final String methodName;
        private final Class<R> type;

        ReflectiveAttributeSetter(String attribute, Class<R> type) {
            this.attribute = attribute;
            this.methodName = "set" + attribute.substring(0, 1).toUpperCase() + attribute.substring(1);
            this.type = type;
        }

        @SuppressWarnings("removal")
        @Override
        public Void apply(O object, R value) {
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            return AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                if (object == null) {
                    throw new NullPointerException("Cannot set " + attribute + " because object is null");
                }

                try {
                    Method method = object.getClass().getMethod(methodName, type);
                    method.invoke(object, value);

                    return null;

                } catch (Exception e) {
                    throw new RuntimeException("Error while set " + attribute + " in " + object + " to " + value, e);
                }
            });
        }
    }

}
