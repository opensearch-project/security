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
import java.security.AccessController;
import java.security.PrivilegedAction;

import com.google.common.base.Preconditions;
import com.google.common.io.BaseEncoding;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.SpecialPermission;
import org.opensearch.core.common.Strings;

import static org.opensearch.security.support.SafeSerializationUtils.isSafeClass;

/**
 * Provides support for Serialization/Deserialization of objects of supported classes into/from Base64 encoded stream
 * using JDK's in-built serialization protocol implemented by the ObjectOutputStream and ObjectInputStream classes.
 */
public class Base64JDKHelper {

    private static final Logger logger = LogManager.getLogger(Base64Helper.class);
    private static final String ODFE_LDAP_USER_CLASS = "com.amazon.dlic.auth.ldap.LdapUser";
    private static final String OS_LDAP_USER_CLASS = "org.opensearch.security.auth.ldap.LdapUser";
    private static final ObjectStreamClass OS_LDAP_USER_CLASS_DESC;

    static {
        try {
            OS_LDAP_USER_CLASS_DESC = ObjectStreamClass.lookup(Class.forName(OS_LDAP_USER_CLASS));
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static class DescriptorNameSetter {
        private static final Field NAME = getField();

        private DescriptorNameSetter() {}

        private static Field getField() {
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

    /**
     * Handles the replacement of a specific class descriptor during serialization.
     * This class is designed to replace the OpenSearch (OS) package name with the
     * OpenDistro for Elasticsearch (ODFE) package name for a single, specific class.
     */
    public static class DescriptorReplacer {
        private static ObjectStreamClass replacementDescriptor;

        static {
            try {
                ObjectStreamClass desc = null;
                try {
                    desc = ObjectStreamClass.lookup(Class.forName(OS_LDAP_USER_CLASS));
                } catch (ClassNotFoundException e) {
                    throw new RuntimeException(e);
                }
                ObjectStreamClass clone = SerializationUtils.clone(desc);
                DescriptorNameSetter.setName(clone, ODFE_LDAP_USER_CLASS);
                replacementDescriptor = clone;
            } catch (Exception e) {
                logger.error("Failed to initialize replacement descriptor", e);
            }
        }

        /**
         * Replaces the class descriptor if it matches the specific OpenSearch class.
         *
         * @param desc The original ObjectStreamClass descriptor.
         * @return The replacement descriptor if the original matches the specific OS class,
         *         otherwise returns the original descriptor.
         */
        public ObjectStreamClass replace(final ObjectStreamClass desc) {
            if (OS_LDAP_USER_CLASS.equals(desc.getName())) {
                return replacementDescriptor;
            }
            return desc;
        }
    }

    private final static class SafeObjectOutputStream extends ObjectOutputStream {

        private static final boolean useSafeObjectOutputStream = checkSubstitutionPermission();
        private static final DescriptorReplacer descriptorReplacer = new DescriptorReplacer();
        private boolean minNodeVersionLowerThan3;

        @SuppressWarnings("removal")
        private static boolean checkSubstitutionPermission() {
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                try {
                    sm.checkPermission(new SpecialPermission());

                    AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                        AccessController.checkPermission(SUBSTITUTION_PERMISSION);
                        return null;
                    });
                } catch (SecurityException e) {
                    return false;
                }
            }
            return true;
        }

        static ObjectOutputStream create(ByteArrayOutputStream out, boolean minNodeVersionLowerThan3) throws IOException {
            try {
                return useSafeObjectOutputStream ? new SafeObjectOutputStream(out, minNodeVersionLowerThan3) : new ObjectOutputStream(out);
            } catch (SecurityException e) {
                // As we try to create SafeObjectOutputStream only when necessary permissions are granted, we should
                // not reach here, but if we do, we can still return ObjectOutputStream after resetting ByteArrayOutputStream
                out.reset();
                return new ObjectOutputStream(out);
            }
        }

        @SuppressWarnings("removal")
        private SafeObjectOutputStream(OutputStream out, boolean minNodeVersionBefore3) throws IOException {
            super(out);
            this.minNodeVersionLowerThan3 = minNodeVersionBefore3;

            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            AccessController.doPrivileged((PrivilegedAction<Boolean>) () -> enableReplaceObject(true));
        }

        @Override
        protected Object replaceObject(Object obj) throws IOException {
            Class<?> clazz = obj.getClass();
            if (isSafeClass(clazz)) {
                return obj;
            }
            throw new IOException("Unauthorized serialization attempt " + clazz.getName());
        }

        @Override
        protected void writeClassDescriptor(ObjectStreamClass desc) throws IOException {
            if (this.minNodeVersionLowerThan3) {
                super.writeClassDescriptor(descriptorReplacer.replace(desc));
            }
            super.writeClassDescriptor(desc);
        }
    }

    public static String serializeObject(final Serializable object) {
        return serializeObject(object, false);
    }

    public static String serializeObject(final Serializable object, boolean minNodeVersionLowerThan3) {

        Preconditions.checkArgument(object != null, "object must not be null");

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (final ObjectOutputStream out = SafeObjectOutputStream.create(bos, minNodeVersionLowerThan3)) {
            out.writeObject(object);
        } catch (final Exception e) {
            throw new OpenSearchException("Instance {} of class {} is not serializable", e, object, object.getClass());
        }
        final byte[] bytes = bos.toByteArray();
        return BaseEncoding.base64().encode(bytes);
    }

    public static Serializable deserializeObject(final String string) {

        Preconditions.checkArgument(!Strings.isNullOrEmpty(string), "object must not be null or empty");

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

        /**
         * Overrides the default readClassDescriptor method to handle package name changes.
         * This method is called during deserialization to read the class descriptor of each
         * serialized object. It specifically addresses the migration for LDAPUser class from
         * com.amazon.dlic to org.opensearch.security package
         *
         * @return ObjectStreamClass The class descriptor to use for deserialization.
         *         If the incoming class name matches the old LDAP user class,
         *         it returns the descriptor for the new OpenSearch LDAP user class.
         *         Otherwise, it returns the original descriptor.
         *
         * Note: This method ensures backwards compatibility with data serialized using
         * the old 2.x package structure, allowing seamless deserialization into the
         * new OpenSearch 3.x+ class structure.
         */
        @Override
        protected ObjectStreamClass readClassDescriptor() throws IOException, ClassNotFoundException {
            ObjectStreamClass desc = super.readClassDescriptor();
            if (desc.getName().equals(ODFE_LDAP_USER_CLASS)) {
                return OS_LDAP_USER_CLASS_DESC;
            }
            return desc;
        }

    }
}
