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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import javax.xml.bind.DatatypeConverter;

import org.elasticsearch.ElasticsearchException;

import com.floragunn.searchguard.user.AuthCredentials;
import com.google.common.io.BaseEncoding;

public class Base64Helper {

    public static String encodeBasicHeader(final String username, final String password) {
        return new String(DatatypeConverter.printBase64Binary((username + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8)));
    }

    public static String serializeObject(final Serializable object) {

        if (object == null) {
            throw new IllegalArgumentException("object must not be null");
        }

        try {
            // final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // cipher.init(Cipher.ENCRYPT_MODE, key);
            // final SealedObject sealedobject = new SealedObject(object,
            // cipher);
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

        try {
            final byte[] userr = BaseEncoding.base64().decode(string);
            final ByteArrayInputStream bis = new ByteArrayInputStream(userr);
            final ObjectInputStream in = new ObjectInputStream(bis);
            // final SealedObject ud = (SealedObject) in.readObject();
            return (Serializable) in.readObject();
        } catch (final Exception e) {
            throw new ElasticsearchException(e.toString());
        }
    }
}
