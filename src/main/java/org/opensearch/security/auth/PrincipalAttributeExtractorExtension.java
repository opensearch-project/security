/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth;

import org.opensearch.plugin.wlm.spi.AttributeExtractorExtension;
import org.opensearch.rule.attribute_extractor.AttributeExtractor;
import org.opensearch.security.OpenSearchSecurityPlugin;

/**
 * Extension that provides the extraction logic for {@link PrincipalAttribute} to core workload-management plugin
 */
public class PrincipalAttributeExtractorExtension implements AttributeExtractorExtension {

    private final OpenSearchSecurityPlugin plugin;

    public PrincipalAttributeExtractorExtension(OpenSearchSecurityPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public AttributeExtractor<String> getAttributeExtractor() {
        return new PrincipalExtractor(plugin.getThreadPool());
    }
}
