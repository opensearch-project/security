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

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class HTTPHelperTest {

    /**
     * For performance reasons we don't want to call toLowerCase() on the config prefix constants every time we use them.
     * This test ensures that the constants are already in lowercase.
     * If for whatever reason you have to make them not fully lowercase make sure to update HTTPHelper#isSecurityConfigPrefix.
     */
    @Test
    public void ensureSecurityConfigPrefixConstantsAreLowercase() {
        assertThat(
            ConfigConstants.OPENDISTRO_SECURITY_CONFIG_PREFIX,
            equalTo(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_PREFIX.toLowerCase())
        );
        assertThat(
            ConfigConstants.OPENSEARCH_SECURITY_CONFIG_PREFIX,
            equalTo(ConfigConstants.OPENSEARCH_SECURITY_CONFIG_PREFIX.toLowerCase())
        );
    }

}
