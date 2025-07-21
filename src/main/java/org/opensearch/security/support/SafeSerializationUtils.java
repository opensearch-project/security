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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import com.amazon.dlic.auth.ldap.LdapUser;
import org.ldaptive.AbstractLdapBean;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.SearchEntry;

/**
 * Provides functionality to verify if a class is categorised to be safe for serialization or
 * deserialization by the security plugin.
 * <br/>
 * All methods are package private.
 */
public final class SafeSerializationUtils {

    private static final Set<Class<?>> SAFE_CLASSES = ImmutableSet.of(
        String.class,
        SocketAddress.class,
        InetSocketAddress.class,
        Pattern.class,
        org.opensearch.security.user.User.class,
        org.opensearch.security.user.serialized.User.class,
        SourceFieldsContext.class,
        LdapUser.class,
        SearchEntry.class,
        LdapEntry.class,
        AbstractLdapBean.class,
        LdapAttribute.class
    );

    private static final Set<Class<?>> SAFE_ASSIGNABLE_FROM_CLASSES = ImmutableSet.of(
        InetAddress.class,
        Number.class,
        Collection.class,
        Map.class,
        Enum.class,
        ImmutableMap.class
    );

    private static final Set<String> SAFE_CLASS_NAMES = Collections.singleton("org.ldaptive.LdapAttribute$LdapAttributeValues");
    static final Map<Class<?>, Boolean> safeClassCache = new ConcurrentHashMap<>();

    static boolean isSafeClass(Class<?> cls) {
        return safeClassCache.computeIfAbsent(cls, SafeSerializationUtils::computeIsSafeClass);
    }

    static boolean computeIsSafeClass(Class<?> cls) {
        return cls.isArray() || SAFE_CLASSES.contains(cls) || SAFE_CLASS_NAMES.contains(cls.getName()) || isAssignableFromSafeClass(cls);
    }

    private static boolean isAssignableFromSafeClass(Class<?> cls) {
        for (Class<?> safeClass : SAFE_ASSIGNABLE_FROM_CLASSES) {
            if (safeClass.isAssignableFrom(cls)) {
                return true;
            }
        }
        return false;
    }

    static void prohibitUnsafeClasses(Class<?> clazz) throws IOException {
        if (!isSafeClass(clazz)) {
            throw new IOException("Unauthorized serialization attempt " + clazz.getName());
        }
    }
}
