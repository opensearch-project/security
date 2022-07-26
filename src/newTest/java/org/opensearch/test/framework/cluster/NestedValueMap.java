/*
 * Copyright 2021-2022 floragunn GmbH
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

package org.opensearch.test.framework.cluster;

import java.io.File;
import java.lang.reflect.Array;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.google.common.collect.MapMaker;

public class NestedValueMap extends HashMap<String, Object> {

    private static final long serialVersionUID = 2953312818482932741L;

    private Map<Object, Object> originalToCloneMap;
    private final boolean cloneWhilePut;
    private boolean writable = true;

    public NestedValueMap() {
        originalToCloneMap = new MapMaker().weakKeys().makeMap();
        cloneWhilePut = true;
    }

    public NestedValueMap(int initialCapacity) {
        super(initialCapacity);
        originalToCloneMap = new MapMaker().weakKeys().makeMap();
        cloneWhilePut = true;
    }

    NestedValueMap(Map<Object, Object> originalToCloneMap, boolean cloneWhilePut) {
        this.originalToCloneMap = originalToCloneMap;
        this.cloneWhilePut = cloneWhilePut;
    }

    NestedValueMap(int initialCapacity, Map<Object, Object> originalToCloneMap, boolean cloneWhilePut) {
        super(initialCapacity);
        this.originalToCloneMap = originalToCloneMap;
        this.cloneWhilePut = cloneWhilePut;
    }

    @Override
    public NestedValueMap clone() {
        NestedValueMap result = new NestedValueMap(Math.max(this.size(), 10),
                this.originalToCloneMap != null ? new MapMaker().weakKeys().makeMap() : null, this.cloneWhilePut);

        result.putAll(this);

        return result;
    }

    public NestedValueMap without(String... keys) {
        NestedValueMap result = new NestedValueMap(Math.max(this.size(), 10),
                this.originalToCloneMap != null ? new MapMaker().weakKeys().makeMap() : null, this.cloneWhilePut);

        Set<String> withoutKeySet = new HashSet<>(Arrays.asList(keys));

        for (Map.Entry<String, Object> entry : this.entrySet()) {
            if (!withoutKeySet.contains(entry.getKey())) {
                result.put(entry.getKey(), entry.getValue());
            }
        }

        return result;
    }

    public static NestedValueMap copy(Map<?, ?> data) {
        NestedValueMap result = new NestedValueMap(data.size());

        result.putAllFromAnyMap(data);

        return result;
    }

    public static NestedValueMap copy(Object data) {
        if (data instanceof Map) {
            return copy((Map<?, ?>) data);
        } else {
            NestedValueMap result = new NestedValueMap();
            result.put("_value", data);
            return result;
        }
    }

    public static NestedValueMap createNonCloningMap() {
        return new NestedValueMap(null, false);
    }

    public static NestedValueMap createUnmodifieableMap(Map<?, ?> data) {
        NestedValueMap result = new NestedValueMap(data.size());

        result.putAllFromAnyMap(data);
        result.seal();

        return result;
    }

//    public static NestedValueMap fromJsonString(String jsonString) throws IOException, DocumentParseException, UnexpectedDocumentStructureException {
//        return NestedValueMap.copy(DocReader.json().readObject(jsonString));
//    }
//
//    public static NestedValueMap fromYaml(String yamlString) throws IOException, DocumentParseException {
//        return NestedValueMap.copy(DocReader.yaml().read(yamlString));
//    }
//
//    public static NestedValueMap fromYaml(InputStream inputSteam) throws DocumentParseException, IOException {
//        return NestedValueMap.copy(DocReader.yaml().read(inputSteam));
//    }

    public static NestedValueMap of(String key1, Object value1) {
        NestedValueMap result = new NestedValueMap(1);
        result.put(key1, value1);
        return result;
    }

    public static NestedValueMap of(String key1, Object value1, String key2, Object value2) {
        NestedValueMap result = new NestedValueMap(2);
        result.put(key1, value1);
        result.put(key2, value2);
        return result;
    }

    public static NestedValueMap of(String key1, Object value1, String key2, Object value2, String key3, Object value3) {
        NestedValueMap result = new NestedValueMap(3);
        result.put(key1, value1);
        result.put(key2, value2);
        result.put(key3, value3);

        return result;
    }

    public static NestedValueMap of(String key1, Object value1, String key2, Object value2, String key3, Object value3, Object... furtherEntries) {
        NestedValueMap result = new NestedValueMap(3 + furtherEntries.length);
        result.put(key1, value1);
        result.put(key2, value2);
        result.put(key3, value3);

        for (int i = 0; i < furtherEntries.length - 1; i += 2) {
            result.put(String.valueOf(furtherEntries[i]), furtherEntries[i + 1]);
        }

        return result;
    }
    
    public static NestedValueMap of(Path key1, Object value1) {
        NestedValueMap result = new NestedValueMap(1);
        result.put(key1, value1);
        return result;
    }

    public static NestedValueMap of(Path key1, Object value1, Path key2, Object value2) {
        NestedValueMap result = new NestedValueMap(2);
        result.put(key1, value1);
        result.put(key2, value2);
        return result;
    }

    public static NestedValueMap of(Path key1, Object value1, Path key2, Object value2, Path key3, Object value3) {
        NestedValueMap result = new NestedValueMap(3);
        result.put(key1, value1);
        result.put(key2, value2);
        result.put(key3, value3);

        return result;
    }

    public static NestedValueMap of(Path key1, Object value1, Path key2, Object value2, Path key3, Object value3, Object... furtherEntries) {
        NestedValueMap result = new NestedValueMap(3 + furtherEntries.length);
        result.put(key1, value1);
        result.put(key2, value2);
        result.put(key3, value3);

        for (int i = 0; i < furtherEntries.length - 1; i += 2) {
            result.put(Path.parse(String.valueOf(furtherEntries[i])), furtherEntries[i + 1]);
        }

        return result;
    }

    public Object put(String key, Map<?, ?> data) {
        checkWritable();

        Object result = this.get(key);
        NestedValueMap subMap = this.getOrCreateSubMapAt(key, data.size());

        subMap.putAllFromAnyMap(data);
        return result;
    }

    public void putAll(Map<? extends String, ? extends Object> map) {
        checkWritable();

        for (Map.Entry<?, ?> entry : map.entrySet()) {
            String key = String.valueOf(entry.getKey());
            put(key, entry.getValue());
        }
    }

    public void putAllFromAnyMap(Map<?, ?> map) {
        checkWritable();

        for (Map.Entry<?, ?> entry : map.entrySet()) {
            String key = String.valueOf(entry.getKey());
            put(key, entry.getValue());
        }
    }

    public void overrideLeafs(NestedValueMap map) {
        checkWritable();

        for (Map.Entry<?, ?> entry : map.entrySet()) {
            String key = String.valueOf(entry.getKey());

            if (entry.getValue() instanceof NestedValueMap) {
                NestedValueMap subMap = (NestedValueMap) entry.getValue();

                getOrCreateSubMapAt(key, subMap.size()).overrideLeafs(subMap);
            } else {
                put(key, entry.getValue());
            }
        }
    }

    public Object put(String key, Object object) {
        checkWritable();

        if (object instanceof Map) {
            return put(key, (Map<?, ?>) object);
        }

        return super.put(key, deepCloneObject(object));
    }

    public void put(Path path, Object object) {
        checkWritable();

        if (path.isEmpty()) {
            if (object instanceof Map) {
                putAllFromAnyMap((Map<?, ?>) object);
            } else {
                throw new IllegalArgumentException("put([], " + object + "): If an empty path is given, the object must be of type map");
            }

        } else {
            NestedValueMap subMap = getOrCreateSubMapAtPath(path.withoutLast());
            subMap.put(path.getLast(), object);
        }
    }

    public Object get(Path path) {
        if (path.isEmpty()) {
            return this;
        } else if (path.length() == 1) {
            return this.get(path.getFirst());
        } else {
            Object subObject = this.get(path.getFirst());

            if (subObject instanceof NestedValueMap) {
                return ((NestedValueMap) subObject).get(path.withoutFirst());
            } else {
                return null;
            }
        }
    }

    public void seal() {
        if (!this.writable) {
            return;
        }

        this.writable = false;
        this.originalToCloneMap = null;

        for (Object value : this.values()) {
            if (value instanceof NestedValueMap) {
                NestedValueMap subMap = (NestedValueMap) value;
                subMap.seal();
            } else if (value instanceof Iterable) {
                for (Object subValue : ((Iterable<?>) value)) {
                    if (subValue instanceof NestedValueMap) {
                        NestedValueMap subMap = (NestedValueMap) subValue;
                        subMap.seal();
                    }
                }
            }
        }
    }

//    public String toJsonString() {
//        return DocWriter.json().writeAsString(this);
//    }
//
//    public String toYamlString() {
//        return DocWriter.yaml().writeAsString(this);
//    }

    private Object deepCloneObject(Object object) {
        if (!cloneWhilePut || object == null || isImmutable(object)) {
            return object;
        }

        Object clone = this.originalToCloneMap.get(object);

        if (clone != null) {
            return clone;
        }

        if (object instanceof Set) {
            Set<?> set = (Set<?>) object;
            Set<Object> copy = new HashSet<>(set.size());
            this.originalToCloneMap.put(object, copy);

            for (Object element : set) {
                copy.add(deepCloneObject(element));
            }

            return copy;
        } else if (object instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) object;
            NestedValueMap copy = new NestedValueMap(map.size(), this.originalToCloneMap, this.cloneWhilePut);
            this.originalToCloneMap.put(object, copy);

            for (Map.Entry<?, ?> entry : map.entrySet()) {
                copy.put((String) deepCloneObject(String.valueOf(entry.getKey())), deepCloneObject(entry.getValue()));
            }

            return copy;
        } else if (object instanceof Collection) {
            Collection<?> collection = (Collection<?>) object;
            ArrayList<Object> copy = new ArrayList<>(collection.size());
            this.originalToCloneMap.put(object, copy);

            for (Object element : collection) {
                copy.add(deepCloneObject(element));
            }

            return copy;
        } else if (object.getClass().isArray()) {
            int length = Array.getLength(object);
            Object copy = Array.newInstance(object.getClass().getComponentType(), length);
            this.originalToCloneMap.put(object, copy);

            for (int i = 0; i < length; i++) {
                Array.set(copy, i, deepCloneObject(Array.get(object, i)));
            }

            return copy;
        } else {
            // Hope the best

            return object;
        }
    }

    private boolean isImmutable(Object object) {
        return object instanceof String || object instanceof Number || object instanceof Boolean || object instanceof Void || object instanceof Class
                || object instanceof Character || object instanceof Enum || object instanceof File || object instanceof UUID || object instanceof URL
                || object instanceof URI;
    }

    private NestedValueMap getOrCreateSubMapAt(String key, int capacity) {
        Object value = this.get(key);

        if (value instanceof NestedValueMap) {
            return (NestedValueMap) value;
        } else {
            if (value instanceof Map) {
                capacity = Math.max(capacity, ((Map<?, ?>) value).size());
            }

            NestedValueMap mapValue = new NestedValueMap(capacity, this.originalToCloneMap, this.cloneWhilePut);

            if (value instanceof Map) {
                mapValue.putAllFromAnyMap((Map<?, ?>) value);
            }

            super.put(key, mapValue);
            return mapValue;
        }

    }

    private NestedValueMap getOrCreateSubMapAtPath(Path path) {
        if (path.isEmpty()) {
            return this;
        }

        String pathElement = path.getFirst();
        Path remainingPath = path.withoutFirst();

        Object value = this.get(pathElement);

        if (value instanceof NestedValueMap) {
            NestedValueMap mapValue = (NestedValueMap) value;
            if (remainingPath.isEmpty()) {
                return mapValue;
            } else {
                return mapValue.getOrCreateSubMapAtPath(remainingPath);
            }
        } else {
            NestedValueMap mapValue = new NestedValueMap(this.originalToCloneMap, this.cloneWhilePut);
            super.put(pathElement, mapValue);

            if (remainingPath.isEmpty()) {
                return mapValue;
            } else {
                return mapValue.getOrCreateSubMapAtPath(remainingPath);
            }
        }
    }

    private void checkWritable() {
        if (!writable) {
            throw new UnsupportedOperationException("Map is not writable");
        }
    }

    public static class Path {
        private String[] elements;
        private int start;
        private int end;

        public Path(String... elements) {
            this.elements = elements;
            this.start = 0;
            this.end = elements.length;
        }

        private Path(String[] elements, int start, int end) {
            this.elements = elements;
            this.start = start;
            this.end = end;
        }

        public String getFirst() {
            if (this.start >= this.end) {
                return null;
            }

            return this.elements[start];
        }

        public String getLast() {
            if (this.start >= this.end) {
                return null;
            }

            return this.elements[end - 1];
        }

        public Path withoutFirst() {
            if (this.start >= this.end - 1) {
                return new Path(null, 0, 0);
            }

            return new Path(elements, start + 1, end);
        }

        public Path withoutLast() {
            if (this.start >= this.end - 1) {
                return new Path(null, 0, 0);
            }

            return new Path(elements, start, end - 1);
        }

        public int length() {
            return this.end - this.start;
        }

        public boolean isEmpty() {
            return this.start == this.end;
        }

        public static Path parse(String path) {
            if (path.length() == 0) {
                return new Path(new String [0]);
            } else {
                return new Path(path.split("\\."));
            }
        }
    }

}
