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

import org.opensearch.Version;

public enum SerializationFormat {
    /** Uses Java's native serialization system */
    JDK,
    /** Uses a custom serializer built ontop of OpenSearch 2.11 */
    CustomSerializer_2_11;

    private static final Version FIRST_CUSTOM_SERIALIZATION_SUPPORTED_OS_VERSION = Version.V_2_11_0;
    private static final Version CUSTOM_SERIALIZATION_NO_LONGER_SUPPORTED_OS_VERSION = Version.V_2_14_0;

    /**
     * Determines the format of serialization that should be used from a version identifier
     */
    public static SerializationFormat determineFormat(final Version version) {
        if (version.onOrAfter(FIRST_CUSTOM_SERIALIZATION_SUPPORTED_OS_VERSION)
            && version.before(CUSTOM_SERIALIZATION_NO_LONGER_SUPPORTED_OS_VERSION)) {
            return SerializationFormat.CustomSerializer_2_11;
        }
        return SerializationFormat.JDK;
    }
}
