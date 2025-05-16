package org.opensearch.sample;

import org.opensearch.security.spi.SecurePluginExtension;

public class SampleSecurePluginExtension implements SecurePluginExtension {
    @Override
    public String getPluginCanonicalClassname() {
        return SampleResourcePlugin.class.getCanonicalName();
    }
}
