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
import java.util.HashMap;
import java.util.Map;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import org.opensearch.OpenSearchException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;

/**
 * Registry for any class that does NOT implement the <code>Writeable</code> interface
 * and needs to be serialized over the wire. Supports registration of writer and reader via <code>registerStreamable</code>
 * for such classes and provides methods <code>writeTo</code> and <code>readFrom</code> for objects of such registered classes.
 * <br/>
 * Methods are protected and intended to be accessed from only within the package. (mostly by <code>Base64Helper</code>)
 */
public class StreamableRegistry {

    private static final StreamableRegistry INSTANCE = new StreamableRegistry();
    public final BiMap<Class<?>, Integer> classToIdMap = HashBiMap.create();
    private final Map<Integer, Entry> idToEntryMap = new HashMap<>();

    private StreamableRegistry() {
        registerAllStreamables();
    }

    private static class Entry {
        Writeable.Writer<Object> writer;
        Writeable.Reader<Object> reader;

        Entry(Writeable.Writer<Object> writer, Writeable.Reader<Object> reader) {
            this.writer = writer;
            this.reader = reader;
        }
    }

    private Writeable.Writer<Object> getWriter(Class<?> clazz) {
        if (!classToIdMap.containsKey(clazz)) {
            throw new OpenSearchException(String.format("No writer registered for class %s", clazz.getName()));
        }
        return idToEntryMap.get(classToIdMap.get(clazz)).writer;
    }

    private Writeable.Reader<Object> getReader(int id) {
        if (!idToEntryMap.containsKey(id)) {
            throw new OpenSearchException(String.format("No reader registered for id %s", id));
        }
        return idToEntryMap.get(id).reader;
    }

    private int getId(Class<?> clazz) {
        if (!classToIdMap.containsKey(clazz)) {
            throw new OpenSearchException(String.format("No writer registered for class %s", clazz.getName()));
        }
        return classToIdMap.get(clazz);
    }

    protected boolean isStreamable(Class<?> clazz) {
        return classToIdMap.containsKey(clazz);
    }

    protected void writeTo(StreamOutput out, Object object) throws IOException {
        out.writeByte((byte) getId(object.getClass()));
        getWriter(object.getClass()).write(out, object);
    }

    protected Object readFrom(StreamInput in) throws IOException {
        int id = in.readByte();
        return getReader(id).read(in);
    }

    protected static StreamableRegistry getInstance() {
        return INSTANCE;
    }

    protected void registerStreamable(int streamableId, Class<?> clazz, Writeable.Writer<Object> writer, Writeable.Reader<Object> reader) {
        if (Writeable.class.isAssignableFrom(clazz)) {
            throw new IllegalArgumentException(
                String.format("%s is Writeable and should not be registered as a streamable", clazz.getName())
            );
        }
        classToIdMap.put(clazz, streamableId);
        idToEntryMap.put(streamableId, new Entry(writer, reader));
    }

    protected int getStreamableID(Class<?> clazz) {
        if (!isStreamable(clazz)) {
            throw new OpenSearchException(String.format("class %s is in streamable registry", clazz.getName()));
        } else {
            return classToIdMap.get(clazz);
        }
    }

    /**
     * Register all streamables here.
     * <br/>
     * Caution - Register new streamables towards the end. Removing / reordering a registered streamable will change the typeIDs associated with the streamables
     * causing a breaking change in the serialization format.
     */
    private void registerAllStreamables() {

        // InetSocketAddress
        this.registerStreamable(1, InetSocketAddress.class, (o, v) -> {
            final InetSocketAddress inetSocketAddress = (InetSocketAddress) v;
            o.writeString(inetSocketAddress.getHostString());
            o.writeByteArray(inetSocketAddress.getAddress().getAddress());
            o.writeInt(inetSocketAddress.getPort());
        }, i -> {
            String host = i.readString();
            byte[] addressBytes = i.readByteArray();
            int port = i.readInt();
            return new InetSocketAddress(InetAddress.getByAddress(host, addressBytes), port);
        });
    }

}
