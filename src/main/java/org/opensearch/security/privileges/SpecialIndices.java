package org.opensearch.security.privileges;

import org.opensearch.common.settings.Settings;
import org.opensearch.indices.SystemIndexRegistry;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

/**
 * Contains information regarding system indices and other specially handled indices
 */
public class SpecialIndices {
    private final String securityIndex;
    private final WildcardMatcher manuallyConfiguredSystemIndexMatcher;

    public SpecialIndices(Settings settings) {
        this.securityIndex = settings.get(
                ConfigConstants.SECURITY_CONFIG_INDEX_NAME,
                ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX
        );
        this.manuallyConfiguredSystemIndexMatcher = WildcardMatcher.from(
                settings.getAsList(ConfigConstants.SECURITY_SYSTEM_INDICES_KEY, ConfigConstants.SECURITY_SYSTEM_INDICES_DEFAULT)
        );
    }

    public boolean isUniversallyDeniedIndex(String index) {
        return index.equals(securityIndex);
    }

    public boolean isSystemIndex(String index) {
        return this.manuallyConfiguredSystemIndexMatcher.test(index) || SystemIndexRegistry.matchesSystemIndexPattern(index);
    }


}
