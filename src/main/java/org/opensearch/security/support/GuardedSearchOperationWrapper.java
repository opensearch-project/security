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

package org.opensearch.security.support;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.index.shard.SearchOperationListener;
import org.opensearch.search.internal.ReaderContext;
import org.opensearch.search.internal.SearchContext;
import org.opensearch.transport.TransportRequest;

/**
 * Guarded version of Search Operation Listener to ensure critical request paths succeed
 */
public interface GuardedSearchOperationWrapper {

    static final Logger log = LogManager.getLogger(GuardedSearchOperationWrapper.class);

    void onPreQueryPhase(final SearchContext context);

    void onNewReaderContext(final ReaderContext readerContext);

    void onNewScrollContext(final ReaderContext readerContext);

    void validateReaderContext(final ReaderContext readerContext, final TransportRequest transportRequest);

    void onQueryPhase(final SearchContext searchContext, final long tookInNanos);

    default SearchOperationListener toListener() {
        return new InnerSearchOperationListener(this);
    }

    static class InnerSearchOperationListener implements SearchOperationListener {

        private GuardedSearchOperationWrapper that;

        InnerSearchOperationListener(GuardedSearchOperationWrapper that) {
            this.that = that;
        }

        @Override
        public void onPreQueryPhase(final SearchContext searchContext) {
            try {
                that.onPreQueryPhase(searchContext);
            } catch (final Exception e) {
                searchContext.setTask(null);
                log.error("Cancelled request due to internal error", e);
            }
        }

        @Override
        public void onNewReaderContext(final ReaderContext readerContext) {
            that.onNewReaderContext(readerContext);
        }

        @Override
        public void onNewScrollContext(final ReaderContext readerContext) {
            that.onNewScrollContext(readerContext);
        }

        @Override
        public void validateReaderContext(final ReaderContext readerContext, final TransportRequest transportRequest) {
            that.validateReaderContext(readerContext, transportRequest);
        }

        @Override
        public void onQueryPhase(final SearchContext searchContext, final long tookInNanos) {
            try {
                that.onQueryPhase(searchContext, tookInNanos);
            } catch (final Exception e) {
                searchContext.setTask(null);
                log.error("Cancelled request due to internal error", e);
            }
        }
    }
}
