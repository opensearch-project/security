/*
* SPDX-License-Identifier: Apache-2.0
*/

package org.opensearch.test.framework.cluster;

import java.io.IOException;
import java.time.Duration;
import java.util.SortedSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PortAllocatorTests {

    @Test
    public void releasesPortsAllocatedForStoppedCluster() {
        PortAllocator allocator = new PortAllocator(SocketUtils.SocketType.TCP, Duration.ofMinutes(1));
        SortedSet<Integer> firstAllocation = allocator.allocate("first-cluster", 1, 50000);
        int allocatedPort = firstAllocation.first();

        allocator.release("first-cluster");

        assertThat(allocator.allocateSingle("second-cluster", allocatedPort), is(allocatedPort));
    }

    @Test
    public void serializesPortAllocationWithinTestJvm() throws Exception {
        CountDownLatch contenderStarted = new CountDownLatch(1);
        CountDownLatch contenderAcquiredLock = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try (PortAllocator.PortAllocationLock ignored = PortAllocator.acquireExclusivePortAllocationLock()) {
            executor.submit(() -> {
                contenderStarted.countDown();
                try (PortAllocator.PortAllocationLock contenderLock = PortAllocator.acquireExclusivePortAllocationLock()) {
                    contenderAcquiredLock.countDown();
                } catch (IOException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
            });

            assertTrue(contenderStarted.await(5, TimeUnit.SECONDS));
            assertFalse(contenderAcquiredLock.await(1, TimeUnit.SECONDS));
        } finally {
            executor.shutdown();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }

        assertTrue(contenderAcquiredLock.await(5, TimeUnit.SECONDS));
    }
}
