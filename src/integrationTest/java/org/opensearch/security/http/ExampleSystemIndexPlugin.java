package org.opensearch.security.http;

import org.opensearch.common.settings.Settings;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.SystemIndexPlugin;

import java.util.Collection;
import java.util.Collections;

public class ExampleSystemIndexPlugin extends Plugin implements SystemIndexPlugin {

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        final SystemIndexDescriptor systemIndexDescriptor = new SystemIndexDescriptor(".system-index1", "System index 1");
        return Collections.singletonList(systemIndexDescriptor);
    }
}
