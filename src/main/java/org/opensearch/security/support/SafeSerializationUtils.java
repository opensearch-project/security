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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import org.opensearch.security.auth.UserInjector;
import org.opensearch.security.user.User;

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
        User.class,
        UserInjector.InjectedUser.class,
        SourceFieldsContext.class,
        LdapUser.class,
        SearchEntry.class,
        LdapEntry.class,
        AbstractLdapBean.class,
        LdapAttribute.class
    );

    private static final List<Class<?>> SAFE_ASSIGNABLE_FROM_CLASSES = ImmutableList.of(
        InetAddress.class,
        Number.class,
        Collection.class,
        Map.class,
        Enum.class
    );

    private static final Set<String> SAFE_CLASS_NAMES = Collections.singleton("org.ldaptive.LdapAttribute$LdapAttributeValues");

    static boolean isSafeClass(Class<?> cls) {
        return cls.isArray()
            || SAFE_CLASSES.contains(cls)
            || SAFE_CLASS_NAMES.contains(cls.getName())
            || SAFE_ASSIGNABLE_FROM_CLASSES.stream().anyMatch(c -> c.isAssignableFrom(cls));
    }

    static void prohibitUnsafeClasses(Class<?> clazz) throws IOException {
        if (!isSafeClass(clazz)) {
            throw new IOException("Unauthorized serialization attempt " + clazz.getName());
        }
    }

}
