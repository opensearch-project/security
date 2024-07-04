package org.opensearch.security.privileges;

import org.bouncycastle.cert.ocsp.Req;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.NullAuditLog;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.ConfigModelV7;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModelV7;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.user.User;
import org.opensearch.security.util.MockIndexMetadataBuilder;
import org.opensearch.test.framework.TestSecurityConfig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

public class PrivilegesEvaluatorPeformanceTest2 {

    final static String[] READ_PERMISSIONS = new String[]{
            "indices:data/read*",
            "indices:admin/mappings/fields/get*",
            "indices:admin/resolve/index"
    };

    final static String[] WRITE_PERMISSIONS = new String[]{
            "indices:data/write*",
            "indices:admin/mapping/put"
    };

    final static String[] CRUD_PERMISSIONS = new String[]{
            "indices:data/read*",
            "indices:admin/mappings/fields/get*",
            "indices:admin/resolve/index",
            "indices:data/write*",
            "indices:admin/mapping/put"
    };

    final static String[] CLUSTER_COMPOSITE_OPS_RO = new String[]{
            "indices:data/read/mget",
            "indices:data/read/msearch",
            "indices:data/read/mtv",
            "indices:admin/aliases/exists*",
            "indices:admin/aliases/get*",
            "indices:data/read/scroll",
            "indices:admin/resolve/index"
    };

    final static String[] CLUSTER_COMPOSITE_OPS = new String[]{
            "indices:data/write/bulk",
            "indices:admin/aliases*",
            "indices:data/write/reindex",
            "indices:data/read/mget",
            "indices:data/read/msearch",
            "indices:data/read/mtv",
            "indices:admin/aliases/exists*",
            "indices:admin/aliases/get*",
            "indices:data/read/scroll",
            "indices:admin/resolve/index"
    };


    final static TestSecurityConfig.User FULL_PRIVILEGES_TEST_USER = new TestSecurityConfig.User("full_privileges").roles(
            new TestSecurityConfig.Role("full_privileges_role").indexPermissions("*").on("*").clusterPermissions("*")
    );

    final static TestSecurityConfig.User LIMITED_PRIVILEGES_1_ROLE_USER = new TestSecurityConfig.User("limited_privileges_one_role").roles(
            new TestSecurityConfig.Role("role").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a*", "index_b*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS)
    );

    final static TestSecurityConfig.User LIMITED_PRIVILEGES_20_ROLES_USER = new TestSecurityConfig.User("limited_privileges_20_roles").roles(
            new TestSecurityConfig.Role("role1").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a1*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role2").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a2*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role3").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a3*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role4").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a4*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role5").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a5*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role6").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a6*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role7").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a7*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role8").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a8*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role9").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a9*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role10").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_a0*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role_b1").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_b1*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role_b2").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_b2*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role_b3").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_b3*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role_b4").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_b4*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role_b5").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_b5*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role_b6").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_b6*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role_b7").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_b7*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role_b8").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_b8*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role_b9").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_b9*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("role_b10").indexPermissions(CRUD_PERMISSIONS)
                    .on("index_b0*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS));


    final static TestSecurityConfig.User LIMITED_PRIVILEGES_40_ROLES_USER = new TestSecurityConfig.User("limited_privileges_40_roles").roles(
            new TestSecurityConfig.Role("role1").indexPermissions(READ_PERMISSIONS)
                    .on("index_a1*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role2").indexPermissions(READ_PERMISSIONS)
                    .on("index_a2*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role3").indexPermissions(READ_PERMISSIONS)
                    .on("index_a3*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role4").indexPermissions(READ_PERMISSIONS)
                    .on("index_a4*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role5").indexPermissions(READ_PERMISSIONS)
                    .on("index_a5*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role6").indexPermissions(READ_PERMISSIONS)
                    .on("index_a6*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role7").indexPermissions(READ_PERMISSIONS)
                    .on("index_a7*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role8").indexPermissions(READ_PERMISSIONS)
                    .on("index_a8*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role9").indexPermissions(READ_PERMISSIONS)
                    .on("index_a9*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role10").indexPermissions(READ_PERMISSIONS)
                    .on("index_a0*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role_b1").indexPermissions(READ_PERMISSIONS)
                    .on("index_b1*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role_b2").indexPermissions(READ_PERMISSIONS)
                    .on("index_b2*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role_b3").indexPermissions(READ_PERMISSIONS)
                    .on("index_b3*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role_b4").indexPermissions(READ_PERMISSIONS)
                    .on("index_b4*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role_b5").indexPermissions(READ_PERMISSIONS)
                    .on("index_b5*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role_b6").indexPermissions(READ_PERMISSIONS)
                    .on("index_b6*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role_b7").indexPermissions(READ_PERMISSIONS)
                    .on("index_b7*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role_b8").indexPermissions(READ_PERMISSIONS)
                    .on("index_b8*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role_b9").indexPermissions(READ_PERMISSIONS)
                    .on("index_b9*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("role_b10").indexPermissions(READ_PERMISSIONS)
                    .on("index_b0*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS_RO),
            new TestSecurityConfig.Role("writerole1").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_a1*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole2").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_a2*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole3").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_a3*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole4").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_a4*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole5").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_a5*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole6").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_a6*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole7").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_a7*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole8").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_a8*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole9").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_a9*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole10").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_a0*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole_b1").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_b1*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole_b2").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_b2*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole_b3").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_b3*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole_b4").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_b4*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole_b5").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_b5*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole_b6").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_b6*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole_b7").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_b7*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole_b8").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_b8*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole_b9").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_b9*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS),
            new TestSecurityConfig.Role("writerole_b10").indexPermissions(WRITE_PERMISSIONS)
                    .on("index_b0*")
                    .clusterPermissions(CLUSTER_COMPOSITE_OPS)

    );

    final static TestSecurityConfig.User LIMITED_PRIVILEGES_USER_ATTR_REGEX_1_ROLE_USER = new TestSecurityConfig.User("limited_privileges_one_role_user_attr_regex").attr(
                    "attr_a",
                    "a"

            ).attr("attr_b",
                    "b")
            .roles(
                    new TestSecurityConfig.Role("role").indexPermissions(CRUD_PERMISSIONS)
                            .on("/^index_(${attr_internal_attr_a}|${attr_internal_attr_b}).*/")
                            .clusterPermissions(CLUSTER_COMPOSITE_OPS)
            );

    static final List<ClusterParameters> CLUSTER_PARAMETERS = ClusterParameters.createList();

    static final List<RequestParameters> REQUEST_PARAMETERS = Arrays.asList(
          //  new RequestParameters("indices:data/read/search", "search on 2% of indices", new SearchRequest("index_a1*"), new SearchRequest("index_a2*"), new SearchRequest("index_a3*"), new SearchRequest("index_a4*"), new SearchRequest("index_a5*"), new SearchRequest("index_a6*"), new SearchRequest("index_a7*"), new SearchRequest("index_a8*"), new SearchRequest("index_a9*"), new SearchRequest("index_a0*"), new SearchRequest("index_b1*"), new SearchRequest("index_b2*"), new SearchRequest("index_b3*"), new SearchRequest("index_b4*"), new SearchRequest("index_b5*"), new SearchRequest("index_b6*"), new SearchRequest("index_b7*"), new SearchRequest("index_b8*"), new SearchRequest("index_b9*"), new SearchRequest("index_b0*")),
          //  new RequestParameters("indices:data/read/search", "search on 20% of indices", new SearchRequest("index_a*"), new SearchRequest("index_b2*")),
        //    new RequestParameters("indices:data/write/bulk", "bulk with 10 items", (i) -> createBulkRequests(10, 10, i / 5)),
            new RequestParameters("indices:data/write/bulk[s]", "bulk shard with 10 items", (i) -> createBulkShardRequests(10, 10, i / 5)),
            new RequestParameters("indices:data/write/bulk[s]", "bulk shard with 1000 items", (i) -> createBulkShardRequests(10, 1000, i / 5))


    );

    final static TestSecurityConfig TEST_SECURITY_CONFIG = new TestSecurityConfig().users(
            FULL_PRIVILEGES_TEST_USER,
            LIMITED_PRIVILEGES_1_ROLE_USER,
            LIMITED_PRIVILEGES_20_ROLES_USER,
            LIMITED_PRIVILEGES_40_ROLES_USER,
            LIMITED_PRIVILEGES_USER_ATTR_REGEX_1_ROLE_USER
    );

    final static TestSecurityConfig DNFOF_CONFIG = new TestSecurityConfig().doNotFailOnForbidden(true);

    final int warmupDurationMs = 100 * 1000;
    final int testDurationMs = 50 * 1000;
    final int parallelThreads = 4;


    void execute() {
        System.out.println("Total number of test cases: " + CLUSTER_PARAMETERS.size() * REQUEST_PARAMETERS.size() * TEST_SECURITY_CONFIG.getUsers().size());
        warmUp();
        System.out.println("=======");
        System.out.println("*TESTS*");
        System.out.println("=======");
        run(parallelThreads, testDurationMs, true, new ResultTable());
    }

    void run(int numberOfThreads, int testDurationMs, boolean runGc, ResultTable resultTable) {
        System.out.println("Running " + numberOfThreads + " threads for " + testDurationMs + " ms");
        if (runGc) {
            System.gc();
        }

        for (ClusterParameters clusterParameters : CLUSTER_PARAMETERS) {
            PrivilegesEvaluator subject = clusterParameters.createPrivilegeEvaluator();

            for (RequestParameters requestParameters : REQUEST_PARAMETERS) {
                requestParameters = requestParameters.indices(clusterParameters.numberOfIndices);

                for (TestSecurityConfig.User user : TEST_SECURITY_CONFIG.getUsers()) {
                    TestCase testCase = new TestCase(clusterParameters, requestParameters, user);
                    testCase.run(numberOfThreads, testDurationMs, subject);
                    System.out.println(testCase);

                    if (!testCase.failures.isEmpty()) {
                        System.err.println("*** Test failed");
                        for (Throwable throwable : testCase.failures) {
                            throwable.printStackTrace();
                        }
                    }

                    if (resultTable != null) {
                        resultTable.add(testCase);
                    }
                }
            }
        }

        if (resultTable != null) {
            System.out.println(resultTable.toCsv());
        }
    }

    void warmUp() {
        System.out.println("=======");
        System.out.println("WARM UP");
        System.out.println("=======");
        long start = System.currentTimeMillis();
        run(1, warmupDurationMs / (CLUSTER_PARAMETERS.size() * REQUEST_PARAMETERS.size() * TEST_SECURITY_CONFIG.getUsers().size()), false, new ResultTable());
        System.out.println("Warm up finished; took: " + (System.currentTimeMillis() - start) / 1000 + " seconds");
    }

    PrivilegesEvaluatorPeformanceTest2() {
    }


    class TestCase {
        final ClusterParameters clusterParameters;
        final RequestParameters requestParameters;
        final TestSecurityConfig.User user;

        List<Throwable> failures = new ArrayList<>();
        long numberOfExecutions = 0;
        long totalExecutionTimeNs = 0;
        double totalExecutionTimeS;
        long totalLatencyNs = 0;
        double throughputOpsPerSec;
        double avgLatencyNs;
        double avgLatencyMs;

        TestCase(ClusterParameters clusterParameters, RequestParameters requestParameters, TestSecurityConfig.User user) {
            this.clusterParameters = clusterParameters;
            this.requestParameters = requestParameters;
            this.user = user;
        }

        void run(int numberOfThreads, int testDurationMs, PrivilegesEvaluator subject) {
            List<TestCaseThread> threads = new ArrayList<>(numberOfThreads);

            if (numberOfThreads == 1) {
                TestCaseThread thread = new TestCaseThread(subject, null, testDurationMs);
                threads.add(thread);
                thread.run();
            } else {

                CountDownLatch finishCountDown = new CountDownLatch(numberOfThreads);

                for (int i = 0; i < numberOfThreads; i++) {
                    TestCaseThread thread = new TestCaseThread(subject, finishCountDown, testDurationMs);
                    threads.add(thread);
                    thread.start();
                }

                try {
                    finishCountDown.await();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }

            for (TestCaseThread thread : threads) {
                this.numberOfExecutions += thread.numberOfExecutions;
                this.totalExecutionTimeNs += thread.totalExecutionTime;
                this.totalLatencyNs += thread.totalLatency;

                if (thread.failure != null) {
                    this.failures.add(thread.failure);
                }
            }

            this.totalExecutionTimeS = (double) this.totalExecutionTimeNs / 1_000_000_000d;
            this.throughputOpsPerSec = (double) this.numberOfExecutions / this.totalExecutionTimeS;
            this.avgLatencyNs = (double) this.totalExecutionTimeNs / (double) this.numberOfExecutions;
            this.avgLatencyMs = this.avgLatencyNs / 1_000_000d;
        }

        @Override
        public String toString() {
            return clusterParameters + "/" + requestParameters.description + "/" + user.getName() + ":\n" +
                    "Took: " + totalExecutionTimeS + "s\n" +
                    "Throughput: " + throughputOpsPerSec + " ops/s\n" + "Average latency: " + avgLatencyMs + "ms\n\n";
        }

        class TestCaseThread extends java.lang.Thread {
            final PrivilegesEvaluator subject;
            final FastAndVeryPseudoRandom random = new FastAndVeryPseudoRandom();
            final CountDownLatch finishCountDown;
            final int testDurationMs;

            Throwable failure;
            int numberOfExecutions;
            long totalExecutionTime;
            long totalLatency;

            TestCaseThread(PrivilegesEvaluator subject, CountDownLatch finishCountDown, int testDurationMs) {
                this.subject = subject;
                this.finishCountDown = finishCountDown;
                this.testDurationMs = testDurationMs;
            }

            @Override
            public void run() {
                try {
                    PrivilegesEvaluator subject = this.subject;
                    long start = System.nanoTime();
                    long now = start;
                    long endAfter = start + this.testDurationMs * 1_000_000l;
                    long sumLatency = 0;
                    int i;
                    for (i = 0; now < endAfter; i++) {
                        long singleStart = System.nanoTime();
                        single(subject);
                        now = System.nanoTime();
                        sumLatency += (now - singleStart);
                    }

                    long end = now;
                    this.numberOfExecutions = i;
                    this.totalExecutionTime = end - start;
                    this.totalLatency = sumLatency;

                } catch (Throwable e) {
                    this.failure = e;
                } finally {
                    if (finishCountDown != null) {
                        finishCountDown.countDown();
                    }
                }
            }

            final void single(PrivilegesEvaluator subject) {
                try {
                    PrivilegesEvaluationContext context = subject.createContext(
                            user(user),
                            requestParameters.action,
                            requestParameters.getRequest(this.random),
                            null,
                            null
                    );
                    PrivilegesEvaluatorResponse response = subject.evaluate(context);

                    if (!response.isAllowed()) {
                        throw new RuntimeException("Assertion failed: " + response);
                    }
                } catch (PrivilegesEvaluatorResponse.NotAllowedException e) {
                    throw new RuntimeException(e);
                }
            }
        }


    }

    static class ClusterParameters {
        final int numberOfIndices;
        final boolean doNotFailOnForbidden;

        ClusterParameters(int numberOfIndices, boolean doNotFailOnForbidden) {
            this.numberOfIndices = numberOfIndices;
            this.doNotFailOnForbidden = doNotFailOnForbidden;
        }

        PrivilegesEvaluator createPrivilegeEvaluator() {
            Metadata metadata = testIndices(numberOfIndices);

            ClusterState clusterState = ClusterState.builder(new ClusterName("test_cluster")).metadata(metadata).build();

            ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
            ConfigurationRepository configurationRepository = mock(ConfigurationRepository.class, withSettings().stubOnly());
            IndexNameExpressionResolver indexNameExpressionResolver = new IndexNameExpressionResolver(threadContext);
            AuditLog auditLog = new NullAuditLog();
            Settings settings = Settings.EMPTY;
            PrivilegesInterceptor privilegesInterceptor = new PrivilegesInterceptor(indexNameExpressionResolver, null, null, null) {
                @Override
                public ReplaceResult replaceDashboardsIndex(
                        final ActionRequest request,
                        final String action,
                        final User user,
                        final DynamicConfigModel config,
                        final IndexResolverReplacer.Resolved requestedResolved,
                        final Map<String, Boolean> tenants
                ) {
                    return PrivilegesInterceptor.CONTINUE_EVALUATION_REPLACE_RESULT;
                }
            };

            IndexResolverReplacer indexResolverReplacer = new IndexResolverReplacer(indexNameExpressionResolver, () -> clusterState, null);
            NamedXContentRegistry namedXContentRegistry = NamedXContentRegistry.EMPTY;

            DynamicConfigModelV7 dynamicConfigModel = new DynamicConfigModelV7(
                    doNotFailOnForbidden
                            ? DNFOF_CONFIG.getSecurityConfiguration().getCEntry("config")
                            : TEST_SECURITY_CONFIG.getSecurityConfiguration().getCEntry("config"),
                    settings,
                    null,
                    null,
                    null
            );
            ConfigModelV7 configModel = new ConfigModelV7(
                    TEST_SECURITY_CONFIG.getRolesConfiguration(),
                    TEST_SECURITY_CONFIG.getRoleMappingsConfiguration(),
                    TEST_SECURITY_CONFIG.geActionGroupsConfiguration(),
                    SecurityDynamicConfiguration.empty(),
                    dynamicConfigModel,
                    settings
            );

            PrivilegesEvaluator privilegesEvaluator = new PrivilegesEvaluator(
                    null,
                    () -> clusterState,
                    threadContext,
                    configurationRepository,
                    indexNameExpressionResolver,
                    auditLog,
                    settings,
                    privilegesInterceptor,
                    null,
                    indexResolverReplacer,
                    namedXContentRegistry
            );
            privilegesEvaluator.updateConfiguration(
                    TEST_SECURITY_CONFIG.geActionGroupsConfiguration(),
                    TEST_SECURITY_CONFIG.getRolesConfiguration()
            );
            privilegesEvaluator.onDynamicConfigModelChanged(dynamicConfigModel);
            privilegesEvaluator.onConfigModelChanged(configModel);

            return privilegesEvaluator;
        }

        static Metadata testIndices(int count) {
            MockIndexMetadataBuilder builder = new MockIndexMetadataBuilder();
            char[] letters = new char[]{'a', 'b', 'c', 'd', 'e'};
            int indicesPerLetter = count / letters.length;

            for (char c : letters) {
                for (int i = 0; i < indicesPerLetter; i++) {
                    builder.index("index_" + c + "" + i);
                }
            }

            return builder.build();
        }

        static List<ClusterParameters> createList() {
            List<ClusterParameters> result = new ArrayList<>();

            for (boolean doNotFailOnForbidden : new boolean[]{false}) {
                for (int numberOfIndices : new int[]{10, 30, 100, 300, 1000, 3000, 10000, 30000, 100000}) {
                    result.add(new ClusterParameters(numberOfIndices, doNotFailOnForbidden));
                }
            }

            return result;
        }

        @Override
        public String toString() {
            String result = numberOfIndices + " indices";

            if (doNotFailOnForbidden) {
                result += ";do_not_fail_on_forbidden";
            }

            return result;
        }
    }

    static User user(TestSecurityConfig.User testUser) {
        User user = new User(testUser.getName());
        user.addSecurityRoles(testUser.getRoleNames());
        user.addAttributes(
                testUser.getAttributes()
                        .entrySet()
                        .stream()
                        .map(e -> Map.entry("attr_internal_" + e.getKey(), e.getValue()))
                        .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()))
        );
        return user;
    }

    static class RequestParameters {
        final String action;
        final ActionRequest[] requests;
        final String description;
        final Function<Integer, ActionRequest []>  requestsFunction;

        RequestParameters(String action, String description, ActionRequest... requests) {
            this.action = action;
            this.requests = requests;
            this.description = description;
            this.requestsFunction = null;
        }

        RequestParameters(String action, String description, Function<Integer, ActionRequest []> requestsFunction) {
            this.action = action;
            this.requests = null;
            this.requestsFunction = requestsFunction;
            this.description = description;
        }

        RequestParameters indices(int indices) {
            if (this.requests != null) {
                return this;
            } else {
                ActionRequest [] requests = requestsFunction.apply(indices);
                return new RequestParameters(action, description, requests);
            }
        }

        ActionRequest getRequest(FastAndVeryPseudoRandom random) {
            if (requests.length == 1) {
                return requests[0];
            } else {
                return requests[random.next(requests.length)];
            }
        }
    }

    static BulkShardRequest createBulkShardRequest(int countItems,  int maxIndexIndex, FastAndVeryPseudoRandom random) {
        String index = randomIndices(1, maxIndexIndex, random)[0];

        BulkItemRequest[] items = new BulkItemRequest[countItems];

        for (int i = 0; i < countItems; i++) {
            items[i] = new BulkItemRequest(0, new IndexRequest(index));
        }

        BulkShardRequest result = new BulkShardRequest(new ShardId(index, "", 1), WriteRequest.RefreshPolicy.IMMEDIATE, items);

        return result;
    }

    static BulkShardRequest[] createBulkShardRequests(int count, int items, int maxIndexIndex) {
        FastAndVeryPseudoRandom random = new FastAndVeryPseudoRandom();
        BulkShardRequest[] result = new BulkShardRequest[count];

        for (int i = 0; i < count; i++) {
            result[i] = createBulkShardRequest(items, maxIndexIndex, random);
        }

        return result;
    }


    static BulkRequest createBulkRequest(int countItems, int maxIndexIndex, FastAndVeryPseudoRandom random) {
        String index = randomIndices(1, maxIndexIndex, random)[0];

        BulkRequest result = new BulkRequest();

        for (int i = 0; i < countItems; i++) {
            result.add(new IndexRequest(index));
        }

        return result;
    }

    static BulkRequest[] createBulkRequests(int count, int items, int maxIndexIndex) {
        FastAndVeryPseudoRandom random = new FastAndVeryPseudoRandom();
        BulkRequest[] result = new BulkRequest[count];

        for (int i = 0; i < count; i++) {
            result[i] = createBulkRequest(items, maxIndexIndex, random);
        }

        return result;
    }


    static String[] randomIndices(int indices,  int maxIndexIndex, FastAndVeryPseudoRandom random) {
        Set<String> result = new HashSet<>();

        while (result.size() < indices) {
            char c = random.next(2) == 1 ? 'a' : 'b';
            String index = "index_" + c + "" + random.next(maxIndexIndex);
            result.add(index);
        }

        return result.toArray(new String[0]);
    }

    static class ResultTable {

        final Map<Key, Map<Integer, Cell>> map = new TreeMap<>();

        void add(TestCase testCase) {
            Key key = new Key(testCase.clusterParameters.doNotFailOnForbidden, testCase.requestParameters, testCase.user);
            this.map.computeIfAbsent(key, k -> new TreeMap<>()).put(testCase.clusterParameters.numberOfIndices,
                    new Cell(testCase.throughputOpsPerSec, testCase.avgLatencyMs));


        }

        String toCsv() {
            StringBuilder result = new StringBuilder();

            for (Map.Entry<Key, Map<Integer, Cell>> entry : map.entrySet()) {
                Key key = entry.getKey();
                result.append(key.request).append(",").append(key.user).append(",").append(key.doNoFailOnForbidden ? "dnfof" : "");
                result.append(",").append(key.asString);
                for (Cell cell : entry.getValue().values()) {
                    //result.append(",").append(cell.avgLatencyMs);
                    result.append(",").append(cell.throughputOpsPerSec);
                }

                result.append("\n");
            }

            return result.toString();
        }

        static class Key implements Comparable<Key> {
            final String asString;
            final boolean doNoFailOnForbidden;
            final String request;
            final String user;

            Key(boolean doNoFailOnForbidden, RequestParameters requestParameters, TestSecurityConfig.User user) {
                this.asString = toString(doNoFailOnForbidden, requestParameters, user);
                this.doNoFailOnForbidden = doNoFailOnForbidden;
                this.request = requestParameters.description;
                this.user = user.getName();
            }

            @Override
            public String toString() {
                return asString;
            }

            static String toString(boolean doNoFailOnForbidden, RequestParameters requestParameters, TestSecurityConfig.User user) {
                String result = requestParameters.description + "; " + user.getName();

                if (doNoFailOnForbidden) {
                    result += "; dnfof";
                }

                return result;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                Key key = (Key) o;
                return Objects.equals(asString, key.asString);
            }

            @Override
            public int hashCode() {
                return Objects.hashCode(asString);
            }

            @Override
            public int compareTo(Key key) {
                return asString.compareTo(key.asString);
            }
        }

        static class Cell {
            final double throughputOpsPerSec;
            final double avgLatencyMs;

            public Cell(double throughputOpsPerSec, double avgLatencyMs) {
                this.throughputOpsPerSec = throughputOpsPerSec;
                this.avgLatencyMs = avgLatencyMs;
            }
        }
    }

    static class FastAndVeryPseudoRandom {
        private final static int[][] TABLE = new int[][]{
                new int[]{},
                new int[]{1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0},
                new int[]{2, 2, 2, 1, 2, 1, 2, 2, 2, 1, 2, 1, 0, 2, 1, 0, 0, 2, 0, 2, 2, 2, 0, 0, 1, 0, 0, 1, 2, 1, 1, 1, 2, 1, 0, 1, 1, 1, 2, 0, 1, 1, 0, 2, 2, 1, 2, 2, 1, 0, 0, 2, 0, 2, 0, 2, 2, 2, 2, 1, 2, 0, 2, 1, 1, 2, 1, 2, 1, 1, 0, 0, 2, 0, 1, 2, 2, 2, 0, 2, 2, 1, 0, 0, 0, 2, 2, 0, 0, 2, 0, 0, 2, 1, 2, 1, 1, 0, 2, 2, 2, 1, 2, 2, 0, 1, 2, 2, 1, 1, 2, 0, 1, 0, 0, 2, 1, 2, 1, 2, 0, 0, 2, 0, 2, 1, 1, 0, 1, 1, 2, 2, 0, 2, 1, 0, 2, 2, 0, 2, 2, 1, 2, 0, 1, 1, 0, 1, 0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 1, 1, 1, 2, 1, 0, 2, 0, 2, 2, 1, 1, 2, 1, 1, 1, 1, 1, 2, 1, 2, 2, 1, 0, 0, 1, 2, 2, 0, 0, 2, 0, 2, 0, 1, 2, 2, 0, 1, 0, 0, 0, 1, 0, 1, 2, 0, 1, 1, 0, 1, 0, 0, 2, 2, 0, 2, 2, 2, 1, 0, 1, 0, 1, 2, 2, 1, 0, 2, 2, 0, 1, 0, 0, 0, 0, 2, 2, 2, 0, 2, 1, 0, 2, 1, 1, 1, 2, 1, 2, 2, 1, 2, 2, 2, 0, 2, 2},
                new int[]{3, 2, 1, 2, 3, 2, 3, 2, 3, 2, 2, 3, 2, 1, 0, 0, 3, 2, 0, 3, 2, 0, 0, 0, 0, 0, 0, 1, 3, 3, 0, 1, 3, 1, 0, 3, 1, 2, 0, 1, 3, 1, 3, 0, 0, 0, 2, 2, 1, 3, 3, 2, 2, 2, 0, 1, 3, 3, 1, 1, 1, 3, 0, 3, 2, 0, 2, 2, 1, 3, 1, 1, 3, 2, 2, 2, 2, 0, 1, 0, 2, 2, 1, 1, 2, 2, 3, 2, 3, 0, 0, 2, 1, 2, 0, 0, 0, 0, 3, 1, 3, 2, 1, 2, 0, 1, 2, 0, 3, 1, 3, 3, 0, 3, 0, 2, 2, 2, 0, 3, 0, 3, 1, 2, 2, 1, 3, 3, 1, 0, 3, 2, 3, 1, 0, 1, 2, 0, 1, 0, 1, 2, 0, 0, 1, 3, 1, 3, 2, 0, 0, 1, 3, 1, 0, 3, 2, 0, 2, 0, 3, 3, 2, 3, 0, 1, 2, 2, 2, 2, 0, 3, 2, 1, 0, 2, 0, 3, 2, 3, 1, 2, 0, 2, 0, 1, 3, 0, 1, 0, 3, 2, 3, 3, 1, 2, 2, 0, 2, 2, 3, 2, 0, 3, 0, 3, 0, 3, 0, 0, 1, 0, 3, 2, 0, 2, 2, 1, 3, 2, 1, 1, 1, 3, 3, 2, 1, 0, 1, 0, 2, 2, 1, 1, 2, 0, 1, 2, 0, 3, 1, 1, 2, 2, 2, 0, 2, 3, 2, 2, 0, 1, 2, 2, 3, 3},
                new int[]{3, 2, 2, 2, 2, 4, 1, 1, 3, 0, 2, 2, 3, 2, 1, 0, 3, 3, 0, 0, 4, 4, 3, 4, 4, 3, 3, 2, 1, 0, 4, 2, 3, 3, 2, 3, 4, 4, 3, 2, 2, 3, 3, 0, 2, 4, 3, 1, 4, 2, 2, 3, 4, 4, 4, 1, 0, 3, 3, 0, 1, 3, 4, 2, 3, 4, 2, 4, 2, 1, 1, 2, 3, 0, 2, 0, 2, 0, 4, 3, 2, 3, 1, 3, 4, 1, 4, 4, 1, 1, 2, 3, 3, 2, 1, 1, 1, 1, 0, 2, 3, 2, 3, 1, 4, 4, 4, 4, 1, 4, 2, 1, 2, 4, 4, 4, 2, 3, 3, 3, 1, 4, 1, 4, 2, 2, 0, 3, 3, 4, 3, 0, 0, 4, 2, 1, 2, 4, 4, 0, 0, 0, 2, 0, 2, 2, 1, 2, 1, 2, 3, 3, 4, 4, 0, 2, 0, 1, 0, 4, 2, 0, 3, 2, 2, 2, 1, 0, 0, 2, 2, 0, 3, 4, 1, 2, 1, 1, 3, 0, 3, 4, 2, 3, 3, 4, 2, 2, 2, 2, 4, 3, 0, 4, 1, 3, 3, 4, 0, 0, 1, 3, 0, 2, 1, 2, 0, 3, 2, 4, 0, 3, 1, 0, 4, 0, 0, 4, 3, 1, 3, 3, 2, 0, 2, 0, 3, 4, 0, 2, 2, 2, 0, 2, 2, 2, 4, 1, 2, 0, 1, 4, 4, 3, 4, 4, 1, 0, 0, 3, 2, 4, 0, 3, 2, 4},
                new int[]{5, 2, 1, 1, 0, 5, 2, 2, 2, 5, 5, 4, 1, 3, 3, 4, 0, 4, 4, 5, 1, 5, 3, 5, 3, 1, 0, 2, 3, 5, 3, 0, 0, 2, 0, 2, 1, 5, 4, 2, 0, 1, 3, 0, 2, 0, 0, 1, 1, 3, 2, 1, 2, 1, 5, 1, 2, 1, 4, 1, 4, 5, 2, 4, 3, 0, 4, 1, 4, 1, 5, 3, 4, 3, 2, 0, 2, 5, 2, 5, 1, 4, 3, 3, 1, 3, 4, 3, 3, 3, 3, 2, 4, 4, 2, 4, 0, 5, 3, 3, 0, 1, 3, 0, 4, 4, 3, 3, 0, 4, 3, 0, 2, 4, 1, 5, 3, 3, 0, 5, 4, 4, 1, 5, 0, 2, 5, 1, 1, 3, 0, 2, 3, 0, 5, 3, 4, 5, 0, 2, 5, 4, 4, 0, 4, 1, 1, 4, 1, 1, 5, 4, 4, 5, 4, 4, 4, 0, 2, 3, 0, 5, 4, 0, 4, 2, 2, 0, 0, 5, 5, 3, 2, 5, 5, 5, 1, 0, 4, 3, 2, 5, 4, 5, 2, 0, 5, 5, 3, 2, 4, 3, 5, 4, 1, 5, 5, 5, 4, 1, 0, 1, 5, 1, 2, 1, 4, 3, 1, 4, 1, 4, 5, 1, 3, 5, 2, 2, 4, 5, 3, 0, 1, 3, 2, 0, 0, 5, 1, 0, 3, 4, 1, 1, 5, 5, 4, 0, 3, 1, 4, 4, 2, 0, 5, 5, 0, 0, 5, 2, 0, 1, 1, 2, 5, 1},
                new int[]{2, 3, 3, 2, 1, 5, 6, 3, 3, 0, 6, 0, 0, 0, 4, 0, 5, 1, 2, 3, 0, 4, 6, 2, 4, 0, 3, 6, 0, 1, 2, 4, 2, 6, 3, 6, 6, 3, 0, 2, 6, 4, 4, 2, 4, 1, 1, 3, 1, 5, 4, 2, 6, 3, 3, 0, 5, 0, 4, 1, 5, 1, 2, 0, 1, 6, 6, 5, 1, 2, 0, 5, 2, 0, 3, 5, 4, 1, 2, 5, 1, 1, 4, 5, 1, 6, 0, 3, 5, 5, 3, 0, 2, 3, 5, 3, 5, 6, 0, 4, 3, 0, 6, 0, 1, 1, 6, 5, 6, 2, 4, 6, 6, 4, 3, 2, 2, 4, 3, 1, 6, 4, 0, 6, 1, 3, 4, 4, 4, 0, 6, 5, 4, 2, 4, 4, 2, 2, 2, 3, 2, 2, 1, 3, 1, 1, 0, 5, 3, 4, 4, 2, 2, 0, 1, 3, 6, 6, 2, 0, 4, 0, 6, 4, 6, 0, 2, 2, 5, 2, 6, 2, 1, 5, 2, 2, 0, 3, 2, 4, 5, 1, 3, 3, 4, 5, 4, 6, 6, 4, 6, 0, 6, 2, 3, 3, 6, 1, 0, 1, 6, 5, 6, 0, 3, 2, 1, 6, 4, 0, 5, 6, 2, 4, 3, 6, 4, 6, 4, 0, 6, 6, 0, 4, 0, 6, 6, 0, 0, 0, 4, 2, 4, 1, 0, 6, 6, 1, 1, 5, 3, 0, 3, 0, 0, 5, 1, 6, 5, 2, 4, 4, 4, 1, 3, 1},
                new int[]{3, 6, 3, 7, 7, 4, 3, 4, 3, 1, 1, 4, 1, 1, 7, 2, 6, 5, 7, 7, 0, 1, 6, 5, 4, 3, 5, 7, 3, 7, 4, 5, 6, 2, 0, 5, 1, 3, 3, 6, 0, 7, 4, 1, 4, 2, 2, 4, 7, 7, 3, 1, 3, 2, 2, 1, 4, 4, 7, 5, 6, 5, 5, 0, 5, 2, 2, 4, 4, 7, 5, 4, 7, 2, 5, 4, 6, 7, 6, 0, 3, 1, 5, 3, 0, 2, 3, 4, 1, 5, 7, 1, 0, 0, 4, 0, 2, 7, 7, 5, 2, 0, 4, 5, 0, 0, 7, 3, 3, 2, 6, 0, 6, 5, 1, 2, 6, 6, 7, 0, 6, 6, 5, 0, 6, 5, 5, 6, 6, 4, 3, 3, 1, 0, 7, 3, 5, 0, 1, 7, 2, 4, 3, 5, 6, 2, 4, 1, 1, 7, 3, 0, 0, 2, 4, 2, 2, 7, 7, 3, 3, 0, 0, 0, 2, 4, 7, 5, 4, 0, 2, 5, 3, 6, 7, 3, 7, 3, 5, 2, 5, 5, 0, 2, 7, 6, 5, 2, 6, 4, 1, 3, 6, 1, 7, 0, 3, 6, 3, 0, 1, 0, 6, 2, 2, 2, 2, 3, 4, 1, 7, 2, 7, 3, 2, 1, 0, 5, 5, 4, 3, 1, 3, 0, 3, 6, 1, 4, 1, 4, 1, 4, 6, 5, 7, 2, 7, 5, 0, 6, 6, 7, 5, 7, 3, 7, 6, 2, 7, 7, 4, 1, 2, 5, 4, 5},
                new int[]{5, 0, 2, 1, 0, 3, 1, 5, 6, 1, 5, 7, 3, 3, 3, 2, 0, 1, 0, 2, 7, 0, 6, 0, 7, 3, 1, 6, 1, 6, 6, 5, 1, 4, 6, 1, 7, 5, 0, 0, 5, 8, 6, 4, 4, 1, 4, 5, 4, 8, 5, 2, 8, 2, 0, 2, 5, 8, 1, 4, 6, 5, 0, 7, 2, 1, 8, 0, 1, 1, 7, 0, 7, 7, 3, 8, 0, 3, 7, 1, 6, 7, 6, 6, 4, 0, 5, 7, 6, 5, 1, 5, 0, 7, 6, 6, 8, 4, 0, 6, 5, 1, 1, 7, 7, 5, 8, 7, 4, 0, 4, 1, 6, 4, 0, 0, 7, 3, 0, 8, 7, 7, 6, 8, 4, 8, 2, 7, 1, 0, 5, 4, 5, 5, 0, 8, 1, 2, 2, 3, 7, 1, 5, 5, 7, 6, 8, 1, 2, 2, 6, 7, 1, 7, 0, 8, 8, 6, 8, 4, 5, 0, 8, 2, 1, 4, 6, 8, 7, 8, 5, 8, 4, 4, 1, 0, 1, 5, 7, 3, 0, 0, 1, 3, 7, 8, 7, 5, 8, 4, 0, 6, 8, 1, 7, 2, 8, 4, 3, 5, 1, 8, 5, 8, 1, 7, 1, 5, 5, 1, 3, 0, 4, 8, 4, 8, 7, 7, 2, 0, 5, 5, 3, 4, 7, 5, 1, 1, 8, 8, 5, 7, 5, 4, 4, 6, 7, 2, 4, 3, 4, 5, 5, 4, 5, 8, 3, 5, 1, 5, 8, 7, 5, 6, 3, 6},
                new int[]{0, 4, 0, 1, 6, 4, 3, 5, 2, 8, 6, 9, 3, 5, 3, 7, 4, 2, 7, 1, 0, 0, 2, 5, 5, 9, 6, 8, 4, 1, 9, 7, 6, 5, 4, 4, 8, 3, 0, 9, 8, 9, 4, 8, 1, 5, 1, 7, 3, 0, 4, 6, 9, 5, 7, 2, 4, 4, 1, 1, 5, 6, 1, 3, 8, 0, 3, 7, 2, 3, 4, 2, 0, 4, 9, 3, 6, 2, 8, 9, 4, 0, 0, 7, 9, 2, 8, 3, 3, 5, 0, 3, 7, 6, 2, 1, 0, 5, 1, 8, 7, 0, 9, 4, 8, 2, 9, 3, 9, 5, 5, 5, 6, 3, 4, 0, 0, 9, 3, 0, 4, 8, 6, 4, 0, 2, 0, 9, 9, 1, 7, 0, 3, 1, 0, 4, 9, 0, 9, 3, 7, 2, 4, 0, 3, 7, 7, 0, 7, 8, 1, 6, 3, 2, 6, 3, 0, 8, 6, 5, 1, 3, 8, 1, 9, 9, 6, 6, 2, 9, 8, 9, 1, 4, 1, 9, 7, 5, 3, 0, 5, 3, 1, 0, 7, 5, 2, 2, 4, 7, 5, 7, 1, 9, 0, 7, 9, 7, 9, 8, 3, 6, 4, 7, 8, 7, 9, 8, 4, 4, 4, 8, 9, 4, 9, 3, 5, 3, 2, 8, 4, 3, 3, 8, 0, 5, 2, 6, 6, 4, 5, 7, 2, 3, 7, 1, 9, 1, 8, 7, 6, 5, 1, 6, 0, 3, 4, 9, 1, 8, 5, 8, 7, 3, 2, 9},
                new int[]{4, 2, 0, 10, 8, 6, 0, 8, 5, 2, 10, 1, 9, 9, 7, 2, 7, 0, 7, 7, 9, 1, 3, 8, 5, 7, 4, 3, 0, 9, 7, 3, 2, 4, 10, 10, 0, 10, 9, 10, 1, 9, 2, 1, 0, 1, 2, 5, 3, 2, 0, 2, 6, 6, 2, 10, 0, 2, 7, 9, 10, 10, 2, 2, 8, 2, 8, 2, 7, 4, 0, 3, 2, 4, 4, 4, 5, 3, 9, 9, 1, 7, 7, 3, 3, 2, 1, 7, 2, 10, 1, 7, 2, 8, 6, 8, 10, 1, 3, 5, 6, 3, 6, 4, 7, 7, 7, 10, 2, 3, 4, 1, 3, 7, 10, 6, 4, 8, 7, 5, 7, 9, 10, 3, 4, 6, 0, 7, 3, 8, 6, 5, 6, 7, 7, 0, 6, 1, 10, 8, 1, 8, 5, 3, 1, 10, 10, 5, 0, 0, 5, 9, 1, 9, 1, 7, 6, 3, 9, 7, 10, 5, 3, 2, 7, 0, 10, 9, 5, 8, 9, 4, 1, 6, 7, 4, 8, 9, 2, 1, 4, 3, 9, 4, 7, 10, 3, 5, 7, 9, 8, 6, 5, 9, 8, 10, 2, 10, 0, 2, 10, 0, 5, 2, 10, 3, 6, 8, 8, 4, 10, 5, 5, 1, 3, 2, 7, 9, 1, 1, 0, 8, 2, 9, 3, 5, 4, 7, 1, 10, 8, 1, 6, 8, 0, 1, 6, 0, 9, 3, 6, 10, 2, 2, 8, 1, 6, 9, 6, 5, 5, 7, 8, 8, 3, 8}
        };

        private final int[] pos = new int[10];

        FastAndVeryPseudoRandom() {
            int seed = (int) ((System.currentTimeMillis() ^ (System.currentTimeMillis() >> 8) ^ (System.currentTimeMillis() >> 16)) & 0xff);
            Arrays.fill(this.pos, seed);
        }

        int next(int bound) {
            if (bound <= 1) {
                return 0;
            } else if (bound > 10) {
                if (bound <= 20) {
                    return next(10) + (bound - 10);
                } else if (bound <= 30) {
                    return next(10) + next(6) + next(3) + next(2) + next(1) + (bound - 20);
                } else {
                    int result = 0;

                    while (bound > 30) {
                        result += next(30);
                        bound -= 30;
                    }

                    result += next(bound);
                    return result;
                }
            }

            bound--;

            int table[] = TABLE[bound];
            int pos = this.pos[bound];

            if (pos >= table.length) {
                pos = 0;
            }

            this.pos[bound] = pos + 1;
            return table[pos];
        }
    }

    public static void main(String... args) {
        new PrivilegesEvaluatorPeformanceTest2().execute();
    }
}
