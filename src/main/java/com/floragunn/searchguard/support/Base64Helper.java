/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.support;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.elasticsearch.ElasticsearchException;

import com.floragunn.searchguard.user.User;
import com.google.common.io.BaseEncoding;

public class Base64Helper {

    public static String serializeObject(final Serializable object) {

        if (object == null) {
            throw new IllegalArgumentException("object must not be null");
        }

        try {
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            final ObjectOutputStream out = new ObjectOutputStream(bos);
            out.writeObject(object);
            final byte[] bytes = bos.toByteArray();
            return BaseEncoding.base64().encode(bytes);
        } catch (final Exception e) {
            throw new ElasticsearchException(e.toString());
        }
    }

    public static Serializable deserializeObject(final String string) {

        if (string == null) {
            throw new IllegalArgumentException("string must not be null");
        }

        SafeObjectInputStream in = null;

        try {
            final byte[] userr = BaseEncoding.base64().decode(string);
            final ByteArrayInputStream bis = new ByteArrayInputStream(userr);
            in = new SafeObjectInputStream(bis);
            return (Serializable) in.readObject();
        } catch (final Exception e) {
            throw new ElasticsearchException(e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }
    
    private final static class SafeObjectInputStream extends ObjectInputStream {

        private static final List<String> SAFE_CLASSES = new ArrayList<>();

        static {
            SAFE_CLASSES.add("com.floragunn.dlic.auth.ldap.LdapUser");
            SAFE_CLASSES.add("org.ldaptive.SearchEntry");
        }

        public SafeObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {

            Class<?> clazz = super.resolveClass(desc);

            if (
                    clazz.isArray() ||
                    clazz.equals(String.class) ||
                    clazz.equals(SocketAddress.class) ||
                    clazz.equals(InetSocketAddress.class) ||
                    InetAddress.class.isAssignableFrom(clazz) ||
                    Number.class.isAssignableFrom(clazz) ||
                    Collection.class.isAssignableFrom(clazz) ||
                    Map.class.isAssignableFrom(clazz) ||
                    Enum.class.isAssignableFrom(clazz) ||
                    clazz.equals(User.class) ||
                    SAFE_CLASSES.contains(clazz.getName())
               ) {

                return clazz;
            }

            throw new InvalidClassException("Unauthorized deserialization attempt", clazz.getName());
        }
    }
}
