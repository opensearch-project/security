/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.test.framework;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class AsyncActions {

    /**
     * Using the provided generator create a list of completable futures.
     * @param parrallelism How many calls to the generator should be done at the same time.
     * @param generationCount The total number of calls to the generator to conduct.
     * @return The list of completable futures running on the fork join thread pool.
     */
    public static <T> List<CompletableFuture<T>> generate(final Callable<T> generator, final int parrallelism, final int generationCount) {
        final ForkJoinPool forkJoinPool = new ForkJoinPool(parrallelism);
        return IntStream.rangeClosed(1, generationCount).boxed().map(i -> CompletableFuture.supplyAsync(() -> {
            try {
                return generator.call();
            } catch (final Exception ex) {
                throw new RuntimeException(ex);
            }
        }, forkJoinPool)).collect(Collectors.toList());
    }

    /**
     * Waits for futures for a time period and then returns them a list
     * @param futures Futures to wait for completion with a result
     * @param n Amount of time to wait
     * @param unit Time associated with those units
     * @return Completed results from the futures
     */
    public static <T> List<T> getAll(final List<CompletableFuture<T>> futures, final int n, final TimeUnit unit) {
        final CompletableFuture<Void> futuresCompleted = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
        try {
            futuresCompleted.get(n, unit);
        } catch (final Exception ex) {
            final long completedFutures = futures.stream().filter(CompletableFuture::isDone).count();
            throw new RuntimeException("Unable to wait for all futures to compete, " + completedFutures + " have finished.", ex);
        }

        return futures.stream().map(future -> {
            try {
                return future.get();
            } catch (final Exception ex) {
                throw new RuntimeException(ex);
            }
        }).collect(Collectors.toList());
    }
}
