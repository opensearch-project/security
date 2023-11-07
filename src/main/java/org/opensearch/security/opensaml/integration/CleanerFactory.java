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

package org.opensearch.security.opensaml.integration;

import java.lang.ref.Cleaner;
import java.util.concurrent.ThreadFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.util.concurrent.OpenSearchExecutors;

/**
 * The class was adapted from {@link net.shibboleth.utilities.java.support.primitive.CleanerSupport}.
 * The main reason is that it is only one way to set Cleaner.create()
 * together with cleaners daemon thread factory which is required for OpenSearch
 */
public class CleanerFactory {

    protected final static Logger log = LogManager.getLogger(SecurityXMLObjectProviderInitializer.class);

    private static final ThreadFactory cleanersThreadFactory = OpenSearchExecutors.daemonThreadFactory("cleaners");

    /** Constructor. */
    private CleanerFactory() {}

    public static Cleaner create(final Class<?> requester) {
        // Current approach here is to create a new Cleaner on each call. A given class requester/owner
        // is assumed to call only once and store in static storage.
        log.debug("Creating new java.lang.ref.Cleaner instance requested by class:  {}", requester.getName());
        return Cleaner.create(cleanersThreadFactory);
    }

}
