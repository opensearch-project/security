/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file to be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.http.saml;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class Saml2SettingsProviderTest {

    @Test
    public void buildsPluginsAssertionConsumerEndpoint() {
        assertThat(
            Saml2SettingsProvider.buildAssertionConsumerEndpoint("https://dashboards.example.com"),
            is("https://dashboards.example.com/_plugins/_security/saml/acs")
        );
    }

    @Test
    public void avoidsDuplicatePathSeparator() {
        assertThat(
            Saml2SettingsProvider.buildAssertionConsumerEndpoint("https://dashboards.example.com/"),
            is("https://dashboards.example.com/_plugins/_security/saml/acs")
        );
    }
}
