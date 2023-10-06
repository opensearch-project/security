package org.opensearch.security;

import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.MemoryUsage;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.GZIPOutputStream;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicHeader;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ResourceFocusedTests {
    private static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);
    private static final User LIMITED_USER = new User("limited_user").roles(
        new TestSecurityConfig.Role("limited-role").clusterPermissions(
            "indices:data/read/mget",
            "indices:data/read/msearch",
            "indices:data/read/scroll",
            "cluster:monitor/state",
            "cluster:monitor/health"
        )
            .indexPermissions(
                "indices:data/read/search",
                "indices:data/read/mget*",
                "indices:monitor/settings/get",
                "indices:monitor/stats"
            )
            .on("*")
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, LIMITED_USER)
        .anonymousAuth(false)
        .doNotFailOnForbidden(true)
        .build();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index("document").source(Map.of("foo", "bar", "abc", "xyz")))
                .actionGet();
        }
    }

    @Test
    public void testUnauthenticatedFewBig() {
        // Tweaks:
        final RequestBodySize size = RequestBodySize.XLarge;
        final String requestPath = "/*/_search";
        final int parrallelism = 5;
        final int totalNumberOfRequests = 100;
        final boolean statsPrinter = false;

        runResourceTest(size, requestPath, parrallelism, totalNumberOfRequests, statsPrinter);
    }

    @Test
    public void testUnauthenticatedManyMedium() {
        // Tweaks:
        final RequestBodySize size = RequestBodySize.Medium;
        final String requestPath = "/*/_search";
        final int parrallelism = 20;
        final int totalNumberOfRequests = 10_000;
        final boolean statsPrinter = false;

        runResourceTest(size, requestPath, parrallelism, totalNumberOfRequests, statsPrinter);
    }

    @Test
    public void testUnauthenticatedTonsSmall() {
        // Tweaks:
        final RequestBodySize size = RequestBodySize.Small;
        final String requestPath = "/*/_search";
        final int parrallelism = 100;
        final int totalNumberOfRequests = 1_000_000;
        final boolean statsPrinter = false;

        runResourceTest(size, requestPath, parrallelism, totalNumberOfRequests, statsPrinter);
    }

    private Long runResourceTest(
        final RequestBodySize size,
        final String requestPath,
        final int parrallelism,
        final int totalNumberOfRequests,
        final boolean statsPrinter
    ) {
        final byte[] compressedRequestBody = createCompressedRequestBody(size);
        try (final TestRestClient client = cluster.getRestClient(new BasicHeader("Content-Encoding", "gzip"))) {

            if (statsPrinter) {
                printStats();
            }
            final HttpPost post = new HttpPost(client.getHttpServerUri() + requestPath);
            post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));

            final ForkJoinPool forkJoinPool = new ForkJoinPool(parrallelism);

            final List<CompletableFuture<Void>> waitingOn = IntStream.rangeClosed(1, totalNumberOfRequests)
                .boxed()
                .map(i -> CompletableFuture.runAsync(() -> client.executeRequest(post), forkJoinPool))
                .collect(Collectors.toList());
            Supplier<Long> getCount = () -> waitingOn.stream().filter(cf -> cf.isDone() && !cf.isCompletedExceptionally()).count();

            CompletableFuture<Void> statPrinter = statsPrinter ? CompletableFuture.runAsync(() -> {
                while (true) {
                    printStats();
                    System.out.println(" & Succesful completions: " + getCount.get());
                    try {
                        Thread.sleep(500);
                    } catch (Exception e) {
                        break;
                    }
                }
            }, forkJoinPool) : CompletableFuture.completedFuture(null);

            final CompletableFuture<Void> allOfThem = CompletableFuture.allOf(waitingOn.toArray(new CompletableFuture[0]));

            try {
                allOfThem.get(30, TimeUnit.SECONDS);
                statPrinter.cancel(true);
            } catch (final Exception e) {
                // Ignored
            }

            if (statsPrinter) {
                printStats();
                System.out.println(" & Succesful completions: " + getCount.get());
            }
            return getCount.get();
        }
    }

    static enum RequestBodySize {
        Small(1),
        Medium(1_000),
        XLarge(1_000_000);

        public final int elementCount;

        private RequestBodySize(final int elementCount) {
            this.elementCount = elementCount;
        }
    }

    private byte[] createCompressedRequestBody(final RequestBodySize size) {
        final int repeatCount = size.elementCount;
        final String prefix = "{ \"items\": [";
        final String repeatedElement = IntStream.range(0, 20)
            .mapToObj(n -> ('a' + n) + "")
            .map(n -> '"' + n + '"' + ": 123")
            .collect(Collectors.joining(",", "{", "}"));
        final String postfix = "]}";
        long uncompressedBytesSize = 0;

        try (
            final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            final GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream)
        ) {

            final byte[] prefixBytes = prefix.getBytes(StandardCharsets.UTF_8);
            final byte[] repeatedElementBytes = repeatedElement.getBytes(StandardCharsets.UTF_8);
            final byte[] postfixBytes = postfix.getBytes(StandardCharsets.UTF_8);

            gzipOutputStream.write(prefixBytes);
            uncompressedBytesSize = uncompressedBytesSize + prefixBytes.length;
            for (int i = 0; i < repeatCount; i++) {
                gzipOutputStream.write(repeatedElementBytes);
                uncompressedBytesSize = uncompressedBytesSize + repeatedElementBytes.length;
            }
            gzipOutputStream.write(postfixBytes);
            uncompressedBytesSize = uncompressedBytesSize + postfixBytes.length;
            gzipOutputStream.finish();

            final byte[] compressedRequestBody = byteArrayOutputStream.toByteArray();
            System.out.println(
                "^^^"
                    + String.format(
                        "Original size was %,d bytes, compressed to %,d bytes, ratio %,.2f",
                        uncompressedBytesSize,
                        compressedRequestBody.length,
                        ((double) uncompressedBytesSize / compressedRequestBody.length)
                    )
            );
            return compressedRequestBody;
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    private void printStats() {
        System.out.println("** Stats ");
        printMemory();
        printMemoryPools();
        printGCPools();
    }

    private void printMemory() {
        final Runtime runtime = Runtime.getRuntime();

        final long totalMemory = runtime.totalMemory(); // Total allocated memory
        final long freeMemory = runtime.freeMemory(); // Amount of free memory
        final long usedMemory = totalMemory - freeMemory; // Amount of used memory

        System.out.println("   Memory Total: " + totalMemory + " Free:" + freeMemory + " Used:" + usedMemory);
    }

    private void printMemoryPools() {
        List<MemoryPoolMXBean> memoryPools = ManagementFactory.getMemoryPoolMXBeans();
        for (MemoryPoolMXBean memoryPool : memoryPools) {
            MemoryUsage usage = memoryPool.getUsage();
            System.out.println("   " + memoryPool.getName() + " USED: " + usage.getUsed() + " MAX: " + usage.getMax());
        }
    }

    private void printGCPools() {
        List<GarbageCollectorMXBean> garbageCollectors = ManagementFactory.getGarbageCollectorMXBeans();
        for (GarbageCollectorMXBean garbageCollector : garbageCollectors) {
            System.out.println("   " + garbageCollector.getName() + " COLLECTION TIME: " + garbageCollector.getCollectionTime());
        }
    }

}
