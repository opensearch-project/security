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
import java.security.AccessController;
import java.security.PrivilegedAction;

import com.google.common.base.Preconditions;
import com.google.common.io.BaseEncoding;

import org.opensearch.OpenSearchException;
import org.opensearch.SpecialPermission;
import org.opensearch.core.common.Strings;

import static org.opensearch.security.support.SafeSerializationUtils.isSafeClass;

/**
 * Provides support for Serialization/Deserialization of objects of supported classes into/from Base64 encoded stream
 * using JDK's in-built serialization protocol implemented by the ObjectOutputStream and ObjectInputStream classes.
 */
public class Base64JDKHelper {

    private final static class SafeObjectOutputStream extends ObjectOutputStream {

        private static final boolean useSafeObjectOutputStream = checkSubstitutionPermission();

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

        @SuppressWarnings("removal")
        private SafeObjectOutputStream(OutputStream out) throws IOException {
            super(out);

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
    }
}
