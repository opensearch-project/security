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

import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import org.opensearch.index.shard.SearchOperationListener;
import org.opensearch.search.internal.ReaderContext;
import org.opensearch.search.internal.SearchContext;
import org.opensearch.transport.TransportRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class GuardedSearchOperationWrapperTest {

    @Test
    public void onNewReaderContextCanThrowException() {
        final String expectedExceptionText = "abcd1234";

        DefaultingGuardedSearchOperationWrapper testWrapper = new DefaultingGuardedSearchOperationWrapper() {
            @Override
            public void onNewReaderContext(ReaderContext readerContext) {
                throw new RuntimeException(expectedExceptionText);
            }
        };

        final RuntimeException expectedException = assertThrows(RuntimeException.class, testWrapper::exerciseAllMethods);

        assertThat(expectedException.getMessage(), equalTo(expectedExceptionText));
    }

    @Test
    public void onNewScrollContextCanThrowException() {
        final String expectedExceptionText = "qwerty978";

        DefaultingGuardedSearchOperationWrapper testWrapper = new DefaultingGuardedSearchOperationWrapper() {
            @Override
            public void onNewScrollContext(ReaderContext readerContext) {
                throw new RuntimeException(expectedExceptionText);
            }
        };

        final RuntimeException expectedException = assertThrows(RuntimeException.class, testWrapper::exerciseAllMethods);

        assertThat(expectedException.getMessage(), equalTo(expectedExceptionText));
    }

    @Test
    public void validateReaderContextCanThrowException() {
        final String expectedExceptionText = "validationException";

        DefaultingGuardedSearchOperationWrapper testWrapper = new DefaultingGuardedSearchOperationWrapper() {
            @Override
            public void validateReaderContext(ReaderContext readerContext, TransportRequest transportRequest) {
                throw new RuntimeException(expectedExceptionText);
            }
        };

        final RuntimeException expectedException = assertThrows(RuntimeException.class, testWrapper::exerciseAllMethods);

        assertThat(expectedException.getMessage(), equalTo(expectedExceptionText));
    }

    @Test
    public void onPreQueryPhaseCannotThrow() {
        AtomicReference<SearchContext> calledSearchContext = new AtomicReference<>();
        DefaultingGuardedSearchOperationWrapper testWrapper = new DefaultingGuardedSearchOperationWrapper() {
            @Override
            public void onPreQueryPhase(SearchContext context) {
                calledSearchContext.set(context);
                throw new RuntimeException("EXCEPTIONAL!");
            }
        };

        testWrapper.exerciseAllMethods();

        assertThat(calledSearchContext.get(), notNullValue());
        verify(calledSearchContext.get()).setTask(null);
    }

    @Test
    public void onQueryPhaseCannotThrow() {
        AtomicReference<SearchContext> calledSearchContext = new AtomicReference<>();
        DefaultingGuardedSearchOperationWrapper testWrapper = new DefaultingGuardedSearchOperationWrapper() {
            @Override
            public void onQueryPhase(SearchContext context, long tookInNanos) {
                calledSearchContext.set(context);
                throw new RuntimeException("EXCEPTIONAL!");
            }
        };

        testWrapper.exerciseAllMethods();

        assertThat(calledSearchContext.get(), notNullValue());
        verify(calledSearchContext.get()).setTask(null);
    }

    /** Only use to make testing easier */
    private static class DefaultingGuardedSearchOperationWrapper implements GuardedSearchOperationWrapper {

        @Override
        public void onNewReaderContext(ReaderContext readerContext) {}

        @Override
        public void onNewScrollContext(ReaderContext readerContext) {}

        @Override
        public void onPreQueryPhase(SearchContext context) {}

        @Override
        public void onQueryPhase(SearchContext searchContext, long tookInNanos) {}

        @Override
        public void validateReaderContext(ReaderContext readerContext, TransportRequest transportRequest) {}

        void exerciseAllMethods() {
            final SearchOperationListener sol = this.toListener();
            sol.onNewReaderContext(mock(ReaderContext.class));
            sol.onNewScrollContext(mock(ReaderContext.class));
            sol.onPreQueryPhase(mock(SearchContext.class));
            sol.onQueryPhase(mock(SearchContext.class), 12345L);
            sol.validateReaderContext(mock(ReaderContext.class), mock(TransportRequest.class));
        }
    }
}
