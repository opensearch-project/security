/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import org.hamcrest.MatcherAssert;
import org.junit.Test;

import org.opensearch.security.spi.resources.sharing.RecipientType;
import org.opensearch.security.spi.resources.sharing.RecipientTypeRegistry;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;

public class RecipientTypeRegistryTests {

    @Test
    public void testFromValue() {
        RecipientTypeRegistry.registerRecipientType("ble1", new RecipientType("ble1"));
        RecipientTypeRegistry.registerRecipientType("ble2", new RecipientType("ble2"));

        // Valid Value
        RecipientType type = RecipientTypeRegistry.fromValue("ble1");
        MatcherAssert.assertThat(type, notNullValue());
        MatcherAssert.assertThat(type.type(), is(equalTo("ble1")));

        // Invalid Value
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> RecipientTypeRegistry.fromValue("bleble"));
        MatcherAssert.assertThat("Unknown RecipientType: bleble. Must be 1 of these: [ble1, ble2]", is(equalTo(exception.getMessage())));
    }
}
