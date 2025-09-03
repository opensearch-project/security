package org.opensearch.security.auth;

import org.opensearch.plugin.wlm.spi.AttributeExtension;
import org.opensearch.rule.attribute_extractor.AttributeExtractor;
import org.opensearch.security.OpenSearchSecurityPlugin;

/**
 * Extension that extracts the principal from the thread context
 */
public class PrincipalAttributeExtension implements AttributeExtension {

    private final OpenSearchSecurityPlugin plugin;

    public PrincipalAttributeExtension(OpenSearchSecurityPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public AttributeExtractor<String> getAttributeExtractor() {
        return new PrincipalExtractor(plugin.getThreadPool());
    }
}
