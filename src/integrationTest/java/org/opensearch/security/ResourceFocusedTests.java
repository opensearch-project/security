package org.opensearch.security;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import java.util.zip.GZIPOutputStream;

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
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;

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
    public void testUnauthenticated() {
        final byte[] compressedRequestBody = createCompressedRequestBody();
        try (final TestRestClient client = cluster.getRestClient(new BasicHeader("Content-Encoding", "gzip"))) {

            printStats();
            final HttpPost post = new HttpPost(client.getHttpServerUri() + "/*/_search");
            post.setEntity(new ByteArrayEntity(compressedRequestBody, ContentType.APPLICATION_JSON));

            final ForkJoinPool forkJoinPool = new ForkJoinPool(5);

            final List<CompletableFuture<Void>> waitingOn = IntStream.rangeClosed(0, 100).boxed().map( i ->
                CompletableFuture.runAsync(() -> client.executeRequest(post), forkJoinPool)
            ).collect(Collectors.toList());
            Supplier<Long> getCount = () -> waitingOn.stream().filter(cf -> cf.isDone() && !cf.isCompletedExceptionally()).count();

            CompletableFuture<Void> statPrinter = CompletableFuture.runAsync(() -> {
                while (true) {
                    printStats();
                    System.out.println(" & Succesful completions: " + getCount.get());
                    try {
                        Thread.sleep(500);
                    } catch (Exception e) {
                        break;
                    }
                }
            }, forkJoinPool);


            final CompletableFuture<Void> allOfThem = CompletableFuture.allOf(waitingOn.toArray(new CompletableFuture[0]));

            try {
                allOfThem.join();
                statPrinter.cancel(true);
            } catch (final Exception e) {
                // Ignored
            }

            printStats();
            System.out.println(" & Succesful completions: " + getCount.get());
        }
    }

    private byte[] createCompressedRequestBody() {
        final int repeatCount = 5000000;
        final String prefix = "{ \"items\": [";
        final String repeatedElement = IntStream.range(0, 20)
            .mapToObj(n -> ('a' + n)+"")
            .map(n -> '"' + n + '"' + ": 123")
            .collect(Collectors.joining(",", "{", "}"));
        final String postfix = "]}";
        long uncompressedBytesSize = 0;

        try (final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             final GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream)) {

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
            System.out.println("^^^" + String.format("Original size was %,d bytes, compressed to %,d bytes, ratio %,.2f", uncompressedBytesSize, compressedRequestBody.length, ((double)uncompressedBytesSize / compressedRequestBody.length)));
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