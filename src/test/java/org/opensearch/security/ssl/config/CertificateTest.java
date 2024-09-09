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

package org.opensearch.security.ssl.config;

import java.lang.reflect.Method;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

public class CertificateTest {

    @Test
    public void testGetObjectMethod() {
        try {
            final Method method = Certificate.getObjectMethod();
            assertThat("Method should not be null", method, notNullValue());
            assertThat(
                "One of the expected methods should be available",
                method.getName().equals("getBaseObject") || method.getName().equals("getObject")
            );
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            fail("Exception should not be thrown: " + e.getMessage());
        }
    }

}
