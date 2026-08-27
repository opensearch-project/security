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

package org.opensearch.security.util;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.opensearch.core.action.ActionListener;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.fail;

public class ActionListenerUtils {
    public static class TestActionListener<T> implements ActionListener<T> {
        private final CountDownLatch latch = new CountDownLatch(1);
        private final AtomicReference<T> response = new AtomicReference<>();
        private final AtomicReference<Exception> exception = new AtomicReference<>();

        @Override
        public void onResponse(T result) {
            response.set(result);
            latch.countDown();
        }

        @Override
        public void onFailure(Exception e) {
            exception.set(e);
            latch.countDown();
        }

        public T assertSuccess() {
            waitForCompletion();
            if (exception.get() != null) {
                fail("Expected success but got exception: " + exception.get());
            }
            return response.get();
        }

        public Exception assertException(Class<? extends Exception> expectedExceptionClass) {
            waitForCompletion();
            Exception actualException = exception.get();
            if (actualException == null) {
                fail("Expected exception of type " + expectedExceptionClass.getSimpleName() + " but operation succeeded");
            }
            assertThat("Exception type mismatch", actualException, instanceOf(expectedExceptionClass));
            return actualException;
        }

        void waitForCompletion() {
            try {
                if (!latch.await(5, TimeUnit.SECONDS)) {
                    fail("Test timed out waiting for response");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("Test interrupted: " + e.getMessage());
            }
        }
    }
}
