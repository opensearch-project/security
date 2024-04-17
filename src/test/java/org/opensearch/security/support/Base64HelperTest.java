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
import java.util.HashMap;
import java.util.stream.IntStream;

import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertThat;
import static org.opensearch.security.support.Base64Helper.deserializeObject;
import static org.opensearch.security.support.Base64Helper.serializeObject;
import static org.hamcrest.Matchers.equalTo;

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
        Assert.assertEquals(test, ds(test));
        Assert.assertEquals(test, dsJDK(test));
    }

    @Test
    public void testEnsureJDKSerialized() {
        String test = "string";
        String jdkSerialized = Base64Helper.serializeObject(test, true);
        String customSerialized = Base64Helper.serializeObject(test, false);
        Assert.assertEquals(jdkSerialized, Base64Helper.ensureJDKSerialized(jdkSerialized));
        Assert.assertEquals(jdkSerialized, Base64Helper.ensureJDKSerialized(customSerialized));
    }

    @Test
    public void testDifference() {
        var largeObject = new HashMap<String, Object>();
        var hm = new HashMap<>();
        IntStream.range(0, 100).forEach(i -> {
            hm.put("c" + i, "cvalue" + i);
        });
        IntStream.range(0, 100).forEach(i -> {
            largeObject.put("a" + i, "value");
            largeObject.put("a", "value" + 1);
            largeObject.put("b" + i, hm);
        });

        String jdkSerialized = Base64Helper.serializeObject(largeObject, true);
        String customSerialized = Base64Helper.serializeObject(largeObject, false);

        assertThat(jdkSerialized.length(), equalTo(customSerialized.length()));
    }
}
