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
import java.io.Serializable;

import com.google.common.base.Preconditions;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import com.google.common.io.BaseEncoding;

import org.opensearch.OpenSearchException;
import org.opensearch.common.Nullable;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.io.stream.BytesStreamInput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.security.auth.UserInjector;
import org.opensearch.security.user.User;

import com.amazon.dlic.auth.ldap.LdapUser;

import static org.opensearch.security.support.SafeSerializationUtils.prohibitUnsafeClasses;

/**
 * Provides support for Serialization/Deserialization of objects of supported classes into/from Base64 encoded stream
 * using the OpenSearch's custom serialization protocol implemented by the StreamInput/StreamOutput classes.
 */
public class Base64CustomHelper {

    private enum CustomSerializationFormat {

        WRITEABLE(1),
        STREAMABLE(2),
        GENERIC(3);

        private final int id;

        CustomSerializationFormat(int id) {
            this.id = id;
        }

        static CustomSerializationFormat fromId(int id) {
            switch (id) {
                case 1:
                    return WRITEABLE;
                case 2:
                    return STREAMABLE;
                case 3:
                    return GENERIC;
                default:
                    throw new IllegalArgumentException(String.format("%d is not a valid id", id));
            }
        }

    }

    private static final BiMap<Class<?>, Integer> writeableClassToIdMap = HashBiMap.create();
    private static final StreamableRegistry streamableRegistry = StreamableRegistry.getInstance();

    static {
        registerAllWriteables();
    }

    protected static String serializeObject(final Serializable object) {

        Preconditions.checkArgument(object != null, "object must not be null");
        final BytesStreamOutput streamOutput = new SafeBytesStreamOutput(128);
        Class<?> clazz = object.getClass();
        try {
            prohibitUnsafeClasses(clazz);
            CustomSerializationFormat customSerializationFormat = getCustomSerializationMode(clazz);
            switch (customSerializationFormat) {
                case WRITEABLE:
                    streamOutput.writeByte((byte) CustomSerializationFormat.WRITEABLE.id);
                    streamOutput.writeByte((byte) getWriteableClassID(clazz).intValue());
                    ((Writeable) object).writeTo(streamOutput);
                    break;
                case STREAMABLE:
                    streamOutput.writeByte((byte) CustomSerializationFormat.STREAMABLE.id);
                    streamableRegistry.writeTo(streamOutput, object);
                    break;
                case GENERIC:
                    streamOutput.writeByte((byte) CustomSerializationFormat.GENERIC.id);
                    streamOutput.writeGenericValue(object);
                    break;
                default:
                    throw new IllegalArgumentException(
                        String.format("Could not determine custom serialization mode for class %s", clazz.getName())
                    );
            }
        } catch (final Exception e) {
            throw new OpenSearchException("Instance {} of class {} is not serializable", e, object, object.getClass());
        }
        final byte[] bytes = streamOutput.bytes().toBytesRef().bytes;
        streamOutput.close();
        return BaseEncoding.base64().encode(bytes);
    }

    protected static Serializable deserializeObject(final String string) {

        Preconditions.checkArgument(!Strings.isNullOrEmpty(string), "object must not be null or empty");
        final byte[] bytes = BaseEncoding.base64().decode(string);
        Serializable obj = null;
        try (final BytesStreamInput streamInput = new SafeBytesStreamInput(bytes)) {
            CustomSerializationFormat serializationFormat = CustomSerializationFormat.fromId(streamInput.readByte());
            switch (serializationFormat) {
                case WRITEABLE:
                    final int classId = streamInput.readByte();
                    Class<?> clazz = getWriteableClassFromId(classId);
                    obj = (Serializable) clazz.getConstructor(StreamInput.class).newInstance(streamInput);
                    break;
                case STREAMABLE:
                    obj = (Serializable) streamableRegistry.readFrom(streamInput);
                    break;
                case GENERIC:
                    obj = (Serializable) streamInput.readGenericValue();
                    break;
                default:
                    throw new IllegalArgumentException("Could not determine custom deserialization mode");
            }
            prohibitUnsafeClasses(obj.getClass());
            return obj;
        } catch (final Exception e) {
            throw new OpenSearchException(e);
        }
    }

    private static boolean isWriteable(Class<?> clazz) {
        return Writeable.class.isAssignableFrom(clazz);
    }

    /**
     * Returns integer ID for the registered Writeable class
     * <br/>
     * Protected for testing
     */
    protected static Integer getWriteableClassID(Class<?> clazz) {
        if (!isWriteable(clazz)) {
            throw new OpenSearchException("clazz should implement Writeable ", clazz);
        }
        if (!writeableClassToIdMap.containsKey(clazz)) {
            throw new OpenSearchException("Writeable clazz not registered ", clazz);
        }
        return writeableClassToIdMap.get(clazz);
    }

    private static Class<?> getWriteableClassFromId(int id) {
        return writeableClassToIdMap.inverse().get(id);
    }

    /**
     * Registers the given <code>Writeable</code> class for custom serialization by assigning an incrementing integer ID
     * IDs are stored in a HashBiMap
     * @param clazz class to be registered
     */
    private static void registerWriteable(Class<? extends Writeable> clazz) {
        if (writeableClassToIdMap.containsKey(clazz)) {
            throw new OpenSearchException("writeable clazz is already registered ", clazz.getName());
        }
        int id = writeableClassToIdMap.size() + 1;
        writeableClassToIdMap.put(clazz, id);
    }

    /**
     * Registers all <code>Writeable</code> classes for custom serialization support.
     * Removing existing classes / changing order of registration will cause a breaking change in the serialization protocol
     * as <code>registerWriteable</code> assigns an incrementing integer ID to each of the classes in the order it is called
     * starting from <code>1</code>.
     *<br/>
     * New classes can safely be added towards the end.
     */
    private static void registerAllWriteables() {
        registerWriteable(User.class);
        registerWriteable(LdapUser.class);
        registerWriteable(UserInjector.InjectedUser.class);
        registerWriteable(SourceFieldsContext.class);
    }

    private static CustomSerializationFormat getCustomSerializationMode(Class<?> clazz) {
        if (isWriteable(clazz)) {
            return CustomSerializationFormat.WRITEABLE;
        } else if (streamableRegistry.isStreamable(clazz)) {
            return CustomSerializationFormat.STREAMABLE;
        } else {
            return CustomSerializationFormat.GENERIC;
        }
    }

    private static class SafeBytesStreamOutput extends BytesStreamOutput {

        public SafeBytesStreamOutput(int expectedSize) {
            super(expectedSize);
        }

        @Override
        public void writeGenericValue(@Nullable Object value) throws IOException {
            prohibitUnsafeClasses(value.getClass());
            super.writeGenericValue(value);
        }
    }

    private static class SafeBytesStreamInput extends BytesStreamInput {

        public SafeBytesStreamInput(byte[] bytes) {
            super(bytes);
        }

        @Override
        public Object readGenericValue() throws IOException {
            Object object = super.readGenericValue();
            prohibitUnsafeClasses(object.getClass());
            return object;
        }
    }
}
