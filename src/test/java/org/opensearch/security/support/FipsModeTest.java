/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.support;

import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class FipsModeTest {

    private Supplier<String> originalSupplier;

    @Before
    public void saveSupplier() {
        originalSupplier = FipsMode.envSupplier;
    }

    @After
    public void restoreSupplier() {
        FipsMode.envSupplier = originalSupplier;
    }

    @Test
    public void isEnabled_isTrueOnlyForCaseInsensitiveTrueValue() {
        for (String enabled : new String[] { "true", "TRUE", "True" }) {
            FipsMode.envSupplier = () -> enabled;
            assertThat("expected enabled for: " + enabled, FipsMode.isEnabled(), equalTo(true));
        }
        for (String disabled : new String[] { "false", null, "", "yes" }) {
            FipsMode.envSupplier = () -> disabled;
            assertThat("expected disabled for: " + disabled, FipsMode.isEnabled(), equalTo(false));
        }
    }
}
