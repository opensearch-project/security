/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.support;

import com.amazon.dlic.auth.ldap.LdapUser;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.ldaptive.AbstractLdapBean;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.SearchEntry;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;

import org.opensearch.OpenSearchException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.Strings;

import org.opensearch.security.user.User;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;

public class Base64Helper {
    private static final Logger logger = LogManager.getLogger(Base64Helper.class);

    private static final String ODFE_PACKAGE = "com.amazon.opendistroforelasticsearch";
    private static final String OS_PACKAGE = "org.opensearch";

    private static final Set<Class<?>> SAFE_CLASSES = ImmutableSet.of(
        String.class,
        SocketAddress.class,
        InetSocketAddress.class,
        Pattern.class,
        User.class,
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

    private static final Set<String> SAFE_CLASS_NAMES = Collections.singleton(
        "org.ldaptive.LdapAttribute$LdapAttributeValues"
    );

    private static boolean isSafeClass(Class<?> cls) {
        return cls.isArray() ||
            SAFE_CLASSES.contains(cls) ||
            SAFE_CLASS_NAMES.contains(cls.getName()) ||
            SAFE_ASSIGNABLE_FROM_CLASSES.stream().anyMatch(c -> c.isAssignableFrom(cls));
    }

    private static class DescriptorNameSetter {
        private static final Field NAME = getField();

        private DescriptorNameSetter() {
        }

        private static Field getFieldPrivileged() {
            try {
                final Field field = ObjectStreamClass.class.getDeclaredField("name");
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException | SecurityException e) {
                logger.error("Failed to get ObjectStreamClass declared field", e);
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    throw new RuntimeException(e);
                }
            }
        }

        private static Field getField() {
            SpecialPermission.check();
            return AccessController.doPrivileged((PrivilegedAction<Field>) () -> getFieldPrivileged());
        }

        public static void setName(ObjectStreamClass desc, String name) {
            try {
                logger.debug("replacing descriptor name from [{}] to [{}]", desc.getName(), name);
                NAME.set(desc, name);
            } catch (IllegalAccessException e) {
                logger.error("Failed to replace descriptor name from {} to {}", desc.getName(), name, e);
                throw new OpenSearchException(e);
            }
        }
    }

    private static class DescriptorReplacer {
        private final ConcurrentMap<String, ObjectStreamClass> nameToDescriptor = new ConcurrentHashMap<>();

        public ObjectStreamClass replace(final ObjectStreamClass desc) {
            final String name = desc.getName();
            if (name.startsWith(OS_PACKAGE)) {
                return nameToDescriptor.computeIfAbsent(name, s -> {
                    SpecialPermission.check();
                    // we can't modify original descriptor as it is cached by ObjectStreamClass, create clone
                    final ObjectStreamClass clone = AccessController.doPrivileged(
                        (PrivilegedAction<ObjectStreamClass>)() -> SerializationUtils.clone(desc)
                    );
                    DescriptorNameSetter.setName(clone, s.replace(OS_PACKAGE, ODFE_PACKAGE));
                    return clone;
                });
            }
            return desc;
        }
    }

    private final static class SafeObjectOutputStream extends ObjectOutputStream {

        private static final boolean useSafeObjectOutputStream = checkSubstitutionPermission();

        private final DescriptorReplacer descriptorReplacer = new DescriptorReplacer();

        private static boolean checkSubstitutionPermission() {
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                try {
                    sm.checkPermission(new SpecialPermission());

                    AccessController.doPrivileged((PrivilegedAction<Void>)() -> {
                        AccessController.checkPermission(SUBSTITUTION_PERMISSION);
                        return null;
                    });
                } catch (SecurityException e) {
                    return false;
                }
            }
            return true;
        }

        static ObjectOutputStream create(ByteArrayOutputStream out) throws IOException {
            try {
                return useSafeObjectOutputStream ? new SafeObjectOutputStream(out) : new ObjectOutputStream(out);
            } catch (SecurityException e) {
                // As we try to create SafeObjectOutputStream only when necessary permissions are granted, we should
                // not reach here, but if we do, we can still return ObjectOutputStream after resetting ByteArrayOutputStream
                out.reset();
                return new ObjectOutputStream(out);
            }
        }

        private SafeObjectOutputStream(OutputStream out) throws IOException {
            super(out);

            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            AccessController.doPrivileged(
                (PrivilegedAction<Boolean>) () -> enableReplaceObject(true)
            );
        }

        @Override
        protected void writeClassDescriptor(final ObjectStreamClass desc) throws IOException {
            super.writeClassDescriptor(descriptorReplacer.replace(desc));
        }

        @Override
        protected Object replaceObject(Object obj) throws IOException {
            Class<?> clazz = obj.getClass();
            if (isSafeClass(clazz)) {
                return obj;
            }
            throw new IOException("Unauthorized serialization attempt " + clazz.getName());
        }
    }

    public static String serializeObject(final Serializable object) {

        Preconditions.checkArgument(object != null, "object must not be null");

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (final ObjectOutputStream out = SafeObjectOutputStream.create(bos)) {
            out.writeObject(object);
        } catch (final Exception e) {
            throw new OpenSearchException("Instance {} of class {} is not serializable", e, object, object.getClass());
        }
        final byte[] bytes = bos.toByteArray();
        return BaseEncoding.base64().encode(bytes);
    }

    public static Serializable deserializeObject(final String string) {

        Preconditions.checkArgument(!Strings.isNullOrEmpty(string), "string must not be null or empty");

        final byte[] bytes = BaseEncoding.base64().decode(string);
        final ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        try (SafeObjectInputStream in = new SafeObjectInputStream(bis)) {
            return (Serializable) in.readObject();
        } catch (final Exception e) {
            throw new OpenSearchException(e);
        }
    }

    private final static class SafeObjectInputStream extends ObjectInputStream {

        public SafeObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {

            Class<?> clazz = super.resolveClass(desc);
            if (isSafeClass(clazz)) {
                return clazz;
            }

            throw new InvalidClassException("Unauthorized deserialization attempt ", clazz.getName());
        }

        @Override
        protected ObjectStreamClass readClassDescriptor() throws IOException, ClassNotFoundException {
            ObjectStreamClass desc = super.readClassDescriptor();
            final String name = desc.getName();
            if (name.startsWith(ODFE_PACKAGE)) {
                desc = ObjectStreamClass.lookup(Class.forName(name.replace(ODFE_PACKAGE, OS_PACKAGE)));
                logger.debug("replaced descriptor name from [{}] to [{}]", name, desc.getName());
            }
            return desc;
        }
    }
}
