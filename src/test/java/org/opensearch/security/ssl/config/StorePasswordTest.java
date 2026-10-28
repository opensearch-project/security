/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.config;

import java.nio.file.Path;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.nullValue;

public class StorePasswordTest {

    @Test
    public void equalContentIsEqualAcrossInstances() {
        final var one = StorePassword.of("changeit".toCharArray());
        final var another = StorePassword.of("changeit".toCharArray());

        assertThat(one, is(another));
        assertThat(one.hashCode(), is(another.hashCode()));
    }

    @Test
    public void differentContentIsNotEqual() {
        final var password = StorePassword.of("changeit".toCharArray());

        assertThat(password, is(not(StorePassword.of("changeme".toCharArray()))));
        assertThat(password, is(not(StorePassword.of("its_a_change".toCharArray()))));
        assertThat(password, is(not(StorePassword.of(new char[0]))));
    }

    @Test
    public void noneUnwrapsToNullAndOnlyEqualsItself() {
        assertThat(StorePassword.of(null), is(StorePassword.NONE));
        assertThat(StorePassword.NONE.chars(), is(nullValue()));

        assertThat(StorePassword.NONE, is(not(StorePassword.of("changeit".toCharArray()))));
        assertThat(StorePassword.of("changeit".toCharArray()), is(not(StorePassword.NONE)));
    }

    @Test
    public void toStringDoesNotRevealTheContent() {
        assertThat(StorePassword.of("changeit".toCharArray()).toString(), is(not(containsString("changeit"))));
        assertThat(StorePassword.NONE.toString(), is("<none>"));
    }

    @Test
    public void configurationsHoldingEqualPasswordsAreEqual() {
        final var one = new KeyStoreConfiguration.JdkKeyStoreConfiguration(
            Path.of("keystore.bcfks"),
            "BCFKS",
            "alias",
            StorePassword.of("changeit".toCharArray()),
            StorePassword.of("changeit".toCharArray())
        );
        final var another = new KeyStoreConfiguration.JdkKeyStoreConfiguration(
            Path.of("keystore.bcfks"),
            "BCFKS",
            "alias",
            StorePassword.of("changeit".toCharArray()),
            StorePassword.of("changeit".toCharArray())
        );

        assertThat(one, is(another));
        assertThat(one.toString(), is(not(containsString("changeit"))));
    }
}
