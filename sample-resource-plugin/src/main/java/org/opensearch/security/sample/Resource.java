package org.opensearch.security.sample;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.xcontent.ToXContentFragment;

public abstract class Resource implements NamedWriteable, ToXContentFragment {
    protected abstract String getResourceIndex();
}
