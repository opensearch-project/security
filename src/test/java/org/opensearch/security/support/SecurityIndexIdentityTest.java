/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.support;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.security.dlic.rest.api.SecurityApiDependencies;
import org.opensearch.security.privileges.SpecialIndices;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SecurityIndexIdentityTest {
    @Test
    public void defaultIndexRemainsUnchanged() {
        assertIdentity(Settings.EMPTY, ".opendistro_security");
    }

    @Test
    public void customIndexReplacesDefault() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ".custom-security").build();
        assertIdentity(settings, ".custom-security");
        assertFalse(new SecurityIndexIdentity(settings).isSecurityIndex(".opendistro_security"));
        assertFalse(new SpecialIndices(settings).isUniversallyDeniedIndex(".opendistro_security"));
    }

    @Test
    public void futureAliasAndGenerationsAreNotInferred() {
        SecurityIndexIdentity identity = new SecurityIndexIdentity(Settings.EMPTY);
        for (String name : new String[] { ".opensearch_security", ".opensearch_security-v1-000001", ".opendistro_security-backup" }) {
            assertFalse(identity.isSecurityIndex(name));
            assertFalse(new SpecialIndices(Settings.EMPTY).isUniversallyDeniedIndex(name));
        }
    }

    @Test
    public void matchingIsExactNotWildcardBased() {
        SecurityIndexIdentity identity = new SecurityIndexIdentity(
            Settings.builder().put(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ".custom*").build()
        );
        assertTrue(identity.isSecurityIndex(".custom*"));
        assertFalse(identity.isSecurityIndex(".custom-security"));
    }

    private void assertIdentity(Settings settings, String name) {
        SecurityIndexIdentity identity = new SecurityIndexIdentity(settings);
        assertEquals(name, identity.getName());
        assertTrue(identity.isSecurityIndex(name));
        assertFalse(identity.isSecurityIndex(name + "-other"));
        assertEquals(name, identity.getDescriptor().getIndexPattern());
        assertEquals("Security index", identity.getDescriptor().getDescription());
        assertEquals(SystemIndexDescriptor.class, identity.getDescriptor().getClass());
        assertTrue(new SpecialIndices(settings).isUniversallyDeniedIndex(name));
        assertEquals(name, new SecurityApiDependencies(null, null, null, null, null, settings).securityIndexName());
    }
}
