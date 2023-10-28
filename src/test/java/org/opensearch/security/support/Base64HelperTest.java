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

import org.junit.Test;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import static org.opensearch.security.support.Base64Helper.deserializeObject;
import static org.opensearch.security.support.Base64Helper.serializeObject;

public class Base64HelperTest {

    private static Serializable dsJDK(Serializable s) {
        return deserializeObject(serializeObject(s, true), true);
    }

    private static Serializable ds(Serializable s) {
        return deserializeObject(serializeObject(s));
    }

    /**
     * Just one sanity test comprising invocation of JDK and Custom Serialization.
     *
     * Individual scenarios are covered by Base64CustomHelperTest and Base64JDKHelperTest
     */
    @Test
    public void testSerde() {
        String test = "string";
        assertThat(ds(test), is(test));
        assertThat(dsJDK(test), is(test));
    }

    @Test
    public void testEnsureJDKSerialized() {
        String test = "string";
        String jdkSerialized = Base64Helper.serializeObject(test, true);
        String customSerialized = Base64Helper.serializeObject(test, false);
        assertThat(Base64Helper.ensureJDKSerialized(jdkSerialized), is(jdkSerialized));
        assertThat(Base64Helper.ensureJDKSerialized(customSerialized), is(jdkSerialized));

    }

}
