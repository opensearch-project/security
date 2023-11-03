package net.shibboleth.shared.primitive;

import java.lang.ref.Cleaner;
import javax.annotation.Nonnull;

import org.opensearch.common.util.concurrent.OpenSearchExecutors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CleanerSupport {
    @Nonnull
    private static final Logger LOG = LoggerFactory.getLogger(CleanerSupport.class);

    private CleanerSupport() {}

    @Nonnull
    public static Cleaner getInstance(@Nonnull final Class<?> requester) {
        LOG.debug("Creating new java.lang.ref.Cleaner instance requested by class: {}", requester.getName());
        return Cleaner.create(OpenSearchExecutors.daemonThreadFactory("cleaners"));
    }
}
