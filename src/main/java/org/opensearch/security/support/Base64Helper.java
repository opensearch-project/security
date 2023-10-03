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

import java.io.Serializable;

public class Base64Helper {

    public static String serializeObject(final Serializable object, final boolean useJDKSerialization) {
        return useJDKSerialization ? Base64JDKHelper.serializeObject(object) : Base64CustomHelper.serializeObject(object);
    }

    public static String serializeObject(final Serializable object) {
        return serializeObject(object, false);
    }

    public static Serializable deserializeObject(final String string) {
        return deserializeObject(string, false);
    }

    public static Serializable deserializeObject(final String string, final boolean useJDKDeserialization) {
        return useJDKDeserialization ? Base64JDKHelper.deserializeObject(string) : Base64CustomHelper.deserializeObject(string);
    }

    /**
     * Ensures that the returned string is JDK serialized.
     *
     * If the supplied string is a custom serialized representation, will deserialize it and further serialize using
     * JDK, otherwise returns the string as is.
     *
     * @param string original string, can be JDK or custom serialized
     * @return jdk serialized string
     */
    public static String ensureJDKSerialized(final String string) {
        Serializable serializable;
        try {
            serializable = Base64Helper.deserializeObject(string, false);
        } catch (Exception e) {
            // We received an exception when de-serializing the given string. It is probably JDK serialized.
            // Try to deserialize using JDK
            Base64Helper.deserializeObject(string, true);
            // Since we could deserialize the object using JDK, the string is already JDK serialized, return as is
            return string;
        }
        // If we see an exception now, we want the caller to see it -
        return Base64Helper.serializeObject(serializable, true);
    }
}
