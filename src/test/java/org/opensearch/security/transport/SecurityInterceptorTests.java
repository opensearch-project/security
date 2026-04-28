/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsResponse;
import org.opensearch.action.search.PitService;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.transport.TransportResponse;
import org.opensearch.extensions.ExtensionsManager;
import org.opensearch.indices.IndicesService;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.impl.AuditLogImpl;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserFactory;
import org.opensearch.telemetry.tracing.noop.NoopTracer;
import org.opensearch.test.transport.MockTransport;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Transport.Connection;
import org.opensearch.transport.TransportException;
import org.opensearch.transport.TransportInterceptor.AsyncSender;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestOptions;
import org.opensearch.transport.TransportResponseHandler;
import org.opensearch.transport.TransportService;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static java.util.Collections.emptySet;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SecurityInterceptorTests {

    private SecurityInterceptor securityInterceptor;

    @Mock
    private BackendRegistry backendRegistry;

    @Mock
    private AuditLog auditLog;

    @Mock
    private PrincipalExtractor principalExtractor;

    @Mock
    private InterClusterRequestEvaluator requestEvalProvider;

    @Mock
    private ClusterService clusterService;

    @Mock
    private SslExceptionHandler sslExceptionHandler;

    @Mock
    private ClusterInfoHolder clusterInfoHolder;

    @Mock
    private SSLConfig sslConfig;

    @Mock
    private TransportRequest request;

    @Mock
    private TransportRequestOptions options;

    @SuppressWarnings("unchecked")
    private TransportResponseHandler<TransportResponse> handler = mock(TransportResponseHandler.class);

    private Settings settings;
    private ThreadPool threadPool;
    private ClusterName clusterName = ClusterName.DEFAULT;
    private MockTransport transport;
    private TransportService transportService;
    private OpenSearchSecurityPlugin.GuiceHolder guiceHolder;
    private User user;
    private String action = "testAction";
    private Version remoteNodeVersion = Version.V_2_0_0;

    private InetAddress localAddress;
    private InetAddress remoteAddress;
    private DiscoveryNode localNode;
    private Connection connection1;
    private DiscoveryNode otherNode;
    private Connection connection2;
    private DiscoveryNode remoteNode;
    private Connection connection3;
    private DiscoveryNode otherRemoteNode;
    private Connection connection4;
    private DiscoveryNode remoteNodeWithCustomSerialization;
    private Connection connection5;

    private AsyncSender sender;
    private AsyncSender jdkSerializedSender;
    private AsyncSender customSerializedSender;
    private AtomicReference<CountDownLatch> senderLatch = new AtomicReference<>(new CountDownLatch(1));

    @Before
    public void setup() {

        // Build mocked objects
        MockitoAnnotations.openMocks(this);
        settings = Settings.builder()
            .put("node.name", SecurityInterceptorTests.class.getSimpleName())
            .put("request.headers.default", "1")
            .build();
        threadPool = new ThreadPool(settings);
        securityInterceptor = new SecurityInterceptor(
            settings,
            threadPool,
            backendRegistry,
            auditLog,
            principalExtractor,
            requestEvalProvider,
            clusterService,
            sslExceptionHandler,
            clusterInfoHolder,
            sslConfig,
            () -> true,
            new UserFactory.Simple()
        );

        clusterName = ClusterName.DEFAULT;
        when(clusterService.getClusterName()).thenReturn(clusterName);

        transport = new MockTransport();
        transportService = transport.createTransportService(
            Settings.EMPTY,
            threadPool,
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            boundTransportAddress -> clusterService.state().nodes().get(SecurityInterceptor.class.getSimpleName()),
            null,
            emptySet(),
            NoopTracer.INSTANCE
        );

        guiceHolder = new OpenSearchSecurityPlugin.GuiceHolder(
            mock(RepositoriesService.class),
            transportService,
            mock(IndicesService.class),
            mock(PitService.class),
            mock(ExtensionsManager.class),
            mock(BackendRegistry.class),
            mock(AuditLogImpl.class)
        );

        // Instantiate objects for tests
        user = new User("John Doe");

        request = mock(TransportRequest.class);
        options = mock(TransportRequestOptions.class);
        when(options.type()).thenReturn(TransportRequestOptions.Type.REG);

        localAddress = null;
        remoteAddress = null;
        try {
            localAddress = InetAddress.getByName("0.0.0.0");
            remoteAddress = InetAddress.getByName("1.1.1.1");
        } catch (final UnknownHostException uhe) {
            throw new RuntimeException(uhe);
        }

        localNode = new DiscoveryNode("local-node1", new TransportAddress(localAddress, 1234), Version.CURRENT);
        connection1 = transportService.getConnection(localNode);

        otherNode = new DiscoveryNode("local-node2", new TransportAddress(localAddress, 4321), Version.CURRENT);
        connection2 = transportService.getConnection(otherNode);

        remoteNode = new DiscoveryNode("remote-node", new TransportAddress(localAddress, 6789), remoteNodeVersion);
        connection3 = transportService.getConnection(remoteNode);

        otherRemoteNode = new DiscoveryNode("remote-node2", new TransportAddress(remoteAddress, 9876), remoteNodeVersion);
        connection4 = transportService.getConnection(otherRemoteNode);

        remoteNodeWithCustomSerialization = new DiscoveryNode(
            "remote-node-with-custom-serialization",
            new TransportAddress(localAddress, 7456),
            Version.V_2_12_0
        );
        connection5 = transportService.getConnection(remoteNodeWithCustomSerialization);

        jdkSerializedSender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                User deserializedUser = (User) Base64Helper.deserializeObject(serializedUserHeader);
                assertThat(deserializedUser, is(user));
                senderLatch.get().countDown();
            }
        };

        sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                assertThat(user, is(transientUser));
                senderLatch.get().countDown();
            }
        };

        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
    }

    /**
     * A method to confirm the original thread context is maintained
     * @param user The expected user to be in the transient header
     */
    final void verifyOriginalContext(User user) {

        User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertThat(user, is(transientUser));
        assertNull(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER));
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    final void completableRequestDecorate(
        AsyncSender sender,
        Connection connection,
        String action,
        TransportRequest request,
        TransportRequestOptions options,
        TransportResponseHandler handler,
        DiscoveryNode localNode
    ) {
        securityInterceptor.sendRequestDecorate(sender, connection, action, request, options, handler, localNode);
        verifyOriginalContext(user);
        try {
            senderLatch.get().await(1, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new RuntimeException(e);
        }

        // Reset the latch so another request can be processed
        senderLatch.set(new CountDownLatch(1));
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    final void completableRequestDecorateWithPreviouslyPopulatedHeaders(
        AsyncSender sender,
        Connection connection,
        String action,
        TransportRequest request,
        TransportRequestOptions options,
        TransportResponseHandler handler,
        DiscoveryNode localNode
    ) {
        securityInterceptor.sendRequestDecorate(sender, connection, action, request, options, handler, localNode);
        try {
            senderLatch.get().await(1, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new RuntimeException(e);
        }

        // Reset the latch so another request can be processed
        senderLatch.set(new CountDownLatch(1));
    }

    @Test
    public void testSendRequestDecorateLocalConnection() {

        // local node request
        completableRequestDecorate(sender, connection1, action, request, options, handler, localNode);
        // this is also a local request
        completableRequestDecorate(sender, connection2, action, request, options, handler, otherNode);
    }

    @Test
    public void testSendRequestDecorateRemoteConnection() {

        // this is a remote request
        completableRequestDecorate(jdkSerializedSender, connection3, action, request, options, handler, localNode);
        // this is a remote request where the transport address is different
        completableRequestDecorate(jdkSerializedSender, connection4, action, request, options, handler, localNode);
    }

    @Test
    public void testSendRequestDecorateRemoteConnectionUsesJDKSerialization() {
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER, Base64Helper.serializeObject(user));
        completableRequestDecorateWithPreviouslyPopulatedHeaders(
            jdkSerializedSender,
            connection3,
            action,
            request,
            options,
            handler,
            localNode
        );
    }

    @Test
    public void testSendNoOriginNodeCausesSerialization() {

        // this is a request where the local node is null; have to use the remote connection since the serialization will fail
        completableRequestDecorate(jdkSerializedSender, connection3, action, request, options, handler, null);
    }

    @Test
    public void testSendNoConnectionShouldThrowNPE() {

        // The completable version swallows the NPE so have to call actual method
        assertThrows(
            java.lang.NullPointerException.class,
            () -> securityInterceptor.sendRequestDecorate(jdkSerializedSender, null, action, request, options, handler, localNode)
        );
    }

    @Test
    public void testNullOriginHeaderCausesNoSerialization() {

        // Make the origin null should cause the ensureCorrectHeaders method to populate with Origin.LOCAL.toString()
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, null);
        // This is a different way to get the same result which exercises the origin0 = null logic of ensureCorrectHeaders
        securityInterceptor.sendRequestDecorate(sender, connection1, action, request, options, handler, localNode);
        verifyOriginalContext(user);
    }

    @Test
    public void testNullRemoteAddressCausesNoSerialization() {

        // Make the remote address null should cause the ensureCorrectHeaders to keep the TransportAddress as null ultimately causing local
        // logic to occur
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, null);
        // This is a different way to get the same result which exercises the origin0 = null logic of ensureCorrectHeaders
        completableRequestDecorate(sender, connection1, action, request, options, handler, localNode);
    }

    @Test
    public void testCustomRemoteAddressCausesSerialization() {

        threadPool.getThreadContext()
            .putHeader(
                ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS,
                String.valueOf(new TransportAddress(new InetSocketAddress("8.8.8.8", 80)))
            );
        completableRequestDecorate(jdkSerializedSender, connection3, action, request, options, handler, localNode);
    }

    @Test
    public void testTraceHeaderIsRemoved() {

        threadPool.getThreadContext().putTransient("_opendistro_security_trace", "fake trace value");
        // this case is just for action trace logic validation
        // local node request
        completableRequestDecorate(sender, connection1, action, request, options, handler, localNode);
        // even though we add the trace the restoring handler should remove it from the thread context
        assertFalse(
            threadPool.getThreadContext().getHeaders().keySet().stream().anyMatch(header -> header.startsWith("_opendistro_security_trace"))
        );
    }

    @Test
    public void testFakeHeaderIsIgnored() {

        threadPool.getThreadContext().putHeader("FAKE_HEADER", "fake_value");
        // this is a local request
        completableRequestDecorate(sender, connection1, action, request, options, handler, localNode);
        // this is a remote request
        completableRequestDecorate(jdkSerializedSender, connection3, action, request, options, handler, localNode);
    }

    @Test
    public void testNullHeaderIsIgnored() {

        // Add a null header
        threadPool.getThreadContext().putHeader(null, null);
        threadPool.getThreadContext().putHeader(null, "null");
        // this is a local request
        completableRequestDecorate(sender, connection1, action, request, options, handler, localNode);
        // this is a remote request
        completableRequestDecorate(jdkSerializedSender, connection3, action, request, options, handler, localNode);
    }

    @Test
    public void testFakeHeadersAreIgnored() {

        threadPool.getThreadContext()
            .putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "fake security config request header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER, "fake security origin header");
        threadPool.getThreadContext()
            .putHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER, "fake security remote address header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, "fake dls query header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, "fake fls fields header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, "fake masked field header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, "fake doc allowlist header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE, "fake filter level dls header");
        threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER, "fake dls mode header");
        threadPool.getThreadContext()
            .putHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_FILTER_LEVEL_QUERY_HEADER, "fake dls filter header");
        threadPool.getThreadContext()
            .putHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER, "fake initial action header");
        threadPool.getThreadContext().putHeader("_opendistro_security_source_field_context", "fake source field context value");
        threadPool.getThreadContext()
            .putHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION, "fake injected roles validation string");

        // this is a local request
        completableRequestDecorate(sender, connection1, action, request, options, handler, localNode);
    }

    @Test
    public void testStreamRequestType() {
        TransportRequestOptions streamOptions = mock(TransportRequestOptions.class);
        when(streamOptions.type()).thenReturn(TransportRequestOptions.Type.STREAM);

        completableRequestDecorate(jdkSerializedSender, connection1, action, request, streamOptions, handler, localNode);
    }

    /**
     * Verifies that TASK_RESOURCE_USAGE response header survives context restore
     * in RestoringTransportResponseHandler.handleResponse().
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testTaskResourceUsageResponseHeaderSurvivesContextRestore() {
        final String TASK_RESOURCE_USAGE = "TASK_RESOURCE_USAGE";
        final String resourceUsageValue = "{\"action\":\"indices:data/read/search[phase/query]\","
            + "\"taskId\":1,\"parentTaskId\":2,\"nodeId\":\"dataNode1\","
            + "\"taskResourceUsage\":{\"cpu_time_in_nanos\":123,\"memory_in_bytes\":456}}";

        final AtomicReference<Map<String, List<String>>> responseHeadersAfterRestore = new AtomicReference<>();

        AsyncSender resourceUsageSender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                threadPool.getThreadContext().addResponseHeader(TASK_RESOURCE_USAGE, resourceUsageValue);

                handler.handleResponse((T) new TransportResponse.Empty());

                responseHeadersAfterRestore.set(threadPool.getThreadContext().getResponseHeaders());

                senderLatch.get().countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(resourceUsageSender, connection3, action, request, options, handler, localNode);

        try {
            senderLatch.get().await(1, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new RuntimeException(e);
        }
        senderLatch.set(new CountDownLatch(1));

        Map<String, List<String>> headers = responseHeadersAfterRestore.get();
        assertThat(
            "TASK_RESOURCE_USAGE response header should be present after handleResponse() context restore",
            headers.containsKey(TASK_RESOURCE_USAGE),
            is(true)
        );
        assertThat(
            "TASK_RESOURCE_USAGE response header value should match",
            headers.get(TASK_RESOURCE_USAGE).get(0),
            is(resourceUsageValue)
        );
    }

    /**
     * Verifies that ALL response headers (TASK_RESOURCE_USAGE + arbitrary custom headers)
     * survive context restore in RestoringTransportResponseHandler.handleResponse().
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testMultipleResponseHeadersSurviveContextRestore() {
        final String TASK_RESOURCE_USAGE = "TASK_RESOURCE_USAGE";
        final String resourceUsageValue = "{\"action\":\"indices:data/read/search[phase/query]\","
            + "\"taskId\":3,\"parentTaskId\":4,\"nodeId\":\"dataNode2\","
            + "\"taskResourceUsage\":{\"cpu_time_in_nanos\":789,\"memory_in_bytes\":1024}}";
        final String CUSTOM_HEADER = "X-Custom-Plugin-Header";
        final String customHeaderValue = "custom-plugin-data-value";

        final AtomicReference<Map<String, List<String>>> responseHeadersAfterRestore = new AtomicReference<>();

        AsyncSender multiHeaderSender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                threadPool.getThreadContext().addResponseHeader(TASK_RESOURCE_USAGE, resourceUsageValue);
                threadPool.getThreadContext().addResponseHeader(CUSTOM_HEADER, customHeaderValue);

                handler.handleResponse((T) new TransportResponse.Empty());

                responseHeadersAfterRestore.set(threadPool.getThreadContext().getResponseHeaders());

                senderLatch.get().countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(multiHeaderSender, connection3, action, request, options, handler, localNode);

        try {
            senderLatch.get().await(1, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new RuntimeException(e);
        }
        senderLatch.set(new CountDownLatch(1));

        Map<String, List<String>> headers = responseHeadersAfterRestore.get();

        assertThat(
            "TASK_RESOURCE_USAGE response header should be present after handleResponse() context restore",
            headers.containsKey(TASK_RESOURCE_USAGE),
            is(true)
        );
        assertThat(
            "TASK_RESOURCE_USAGE response header value should match",
            headers.get(TASK_RESOURCE_USAGE).get(0),
            is(resourceUsageValue)
        );
        assertThat(
            "Custom response header should be present after handleResponse() context restore",
            headers.containsKey(CUSTOM_HEADER),
            is(true)
        );
        assertThat("Custom response header value should match", headers.get(CUSTOM_HEADER).get(0), is(customHeaderValue));
    }

    /**
     * Preservation test: ClusterSearchShardsResponse with DLS response header sets
     * OPENDISTRO_SECURITY_DLS_QUERY_CCS transient after handleResponse().
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testPreservation_ClusterSearchShardsResponse_DlsTransientSet() {
        final String dlsValue = "{\"bool\":{\"must\":[{\"term\":{\"department\":\"HR\"}}]}}";
        final AtomicReference<String> dlsTransientAfterRestore = new AtomicReference<>();

        AsyncSender dlsSender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                threadPool.getThreadContext().addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, dlsValue);

                ClusterSearchShardsResponse shardsResponse = new ClusterSearchShardsResponse(null, null, null);
                handler.handleResponse((T) shardsResponse);

                dlsTransientAfterRestore.set(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_CCS));

                senderLatch.get().countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(dlsSender, connection3, action, request, options, handler, localNode);

        try {
            senderLatch.get().await(1, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new RuntimeException(e);
        }
        senderLatch.set(new CountDownLatch(1));

        assertNotNull("DLS CCS transient should be set for ClusterSearchShardsResponse", dlsTransientAfterRestore.get());
        assertThat(dlsTransientAfterRestore.get(), is(dlsValue));
    }

    /**
     * Preservation test: ClusterSearchShardsResponse with FLS response header sets
     * OPENDISTRO_SECURITY_FLS_FIELDS_CCS transient after handleResponse().
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testPreservation_ClusterSearchShardsResponse_FlsTransientSet() {
        final String flsValue = "field1,field2,field3";
        final AtomicReference<String> flsTransientAfterRestore = new AtomicReference<>();

        AsyncSender flsSender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                threadPool.getThreadContext().addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, flsValue);

                ClusterSearchShardsResponse shardsResponse = new ClusterSearchShardsResponse(null, null, null);
                handler.handleResponse((T) shardsResponse);

                flsTransientAfterRestore.set(
                    threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_CCS)
                );

                senderLatch.get().countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(flsSender, connection3, action, request, options, handler, localNode);

        try {
            senderLatch.get().await(1, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new RuntimeException(e);
        }
        senderLatch.set(new CountDownLatch(1));

        assertNotNull("FLS CCS transient should be set for ClusterSearchShardsResponse", flsTransientAfterRestore.get());
        assertThat(flsTransientAfterRestore.get(), is(flsValue));
    }

    /**
     * Preservation test: ClusterSearchShardsResponse with masked fields response header sets
     * OPENDISTRO_SECURITY_MASKED_FIELD_CCS transient after handleResponse().
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testPreservation_ClusterSearchShardsResponse_MaskedFieldTransientSet() {
        final String maskedFieldValue = "ssn,credit_card,phone_number";
        final AtomicReference<String> maskedTransientAfterRestore = new AtomicReference<>();

        AsyncSender maskedSender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                threadPool.getThreadContext().addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, maskedFieldValue);

                ClusterSearchShardsResponse shardsResponse = new ClusterSearchShardsResponse(null, null, null);
                handler.handleResponse((T) shardsResponse);

                maskedTransientAfterRestore.set(
                    threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_CCS)
                );

                senderLatch.get().countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(maskedSender, connection3, action, request, options, handler, localNode);

        try {
            senderLatch.get().await(1, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new RuntimeException(e);
        }
        senderLatch.set(new CountDownLatch(1));

        assertNotNull("Masked field CCS transient should be set for ClusterSearchShardsResponse", maskedTransientAfterRestore.get());
        assertThat(maskedTransientAfterRestore.get(), is(maskedFieldValue));
    }

    /**
     * Preservation test: handleException() restores context and propagates TransportException
     * to the inner handler.
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testPreservation_HandleExceptionRestoresContextAndPropagates() {
        final TransportException testException = new TransportException("test exception for preservation");
        final AtomicReference<TransportException> capturedException = new AtomicReference<>();
        final AtomicReference<User> userAfterRestore = new AtomicReference<>();

        TransportResponseHandler<TransportResponse> capturingHandler = new TransportResponseHandler<TransportResponse>() {
            @Override
            public TransportResponse read(org.opensearch.core.common.io.stream.StreamInput in) {
                return null;
            }

            @Override
            public void handleResponse(TransportResponse response) {}

            @Override
            public void handleException(TransportException exp) {
                capturedException.set(exp);
                userAfterRestore.set(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER));
            }

            @Override
            public String executor() {
                return "same";
            }
        };

        AsyncSender exceptionSender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                handler.handleException(testException);
                senderLatch.get().countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(exceptionSender, connection3, action, request, options, capturingHandler, localNode);

        try {
            senderLatch.get().await(1, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new RuntimeException(e);
        }
        senderLatch.set(new CountDownLatch(1));

        assertNotNull("Exception should be propagated to inner handler", capturedException.get());
        assertThat(capturedException.get().getMessage(), is("test exception for preservation"));

        assertNotNull("User transient should be restored before inner handler receives exception", userAfterRestore.get());
        assertThat(userAfterRestore.get(), is(user));
    }

    /**
     * Preservation test: handleStreamResponse() delegates directly to inner handler
     * without header processing.
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testPreservation_HandleStreamResponseDelegatesDirectly() {
        final AtomicReference<Boolean> streamHandlerCalled = new AtomicReference<>(false);

        TransportResponseHandler<TransportResponse> streamCapturingHandler = new TransportResponseHandler<TransportResponse>() {
            @Override
            public TransportResponse read(org.opensearch.core.common.io.stream.StreamInput in) {
                return null;
            }

            @Override
            public void handleResponse(TransportResponse response) {}

            @Override
            public void handleException(TransportException exp) {}

            @Override
            public void handleStreamResponse(org.opensearch.transport.stream.StreamTransportResponse<TransportResponse> response) {
                streamHandlerCalled.set(true);
            }

            @Override
            public String executor() {
                return "same";
            }
        };

        AsyncSender streamSender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                handler.handleStreamResponse(null);
                senderLatch.get().countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(streamSender, connection3, action, request, options, streamCapturingHandler, localNode);

        try {
            senderLatch.get().await(1, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new RuntimeException(e);
        }
        senderLatch.set(new CountDownLatch(1));

        assertTrue("handleStreamResponse should delegate directly to inner handler", streamHandlerCalled.get());
    }

    /**
     * Preservation test: Non-ClusterSearchShardsResponse responses do NOT set DLS/FLS/masked-field
     * transients even when those response headers are present.
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testPreservation_NonClusterSearchShardsResponse_NoTransientsSet() {
        final String dlsValue = "{\"bool\":{\"must\":[{\"term\":{\"department\":\"HR\"}}]}}";
        final String flsValue = "field1,field2";
        final String maskedValue = "ssn,credit_card";

        final AtomicReference<String> dlsTransient = new AtomicReference<>();
        final AtomicReference<String> flsTransient = new AtomicReference<>();
        final AtomicReference<String> maskedTransient = new AtomicReference<>();

        AsyncSender nonShardsSender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                threadPool.getThreadContext().addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, dlsValue);
                threadPool.getThreadContext().addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, flsValue);
                threadPool.getThreadContext().addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, maskedValue);

                handler.handleResponse((T) new TransportResponse.Empty());

                dlsTransient.set(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_CCS));
                flsTransient.set(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_CCS));
                maskedTransient.set(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_CCS));

                senderLatch.get().countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(nonShardsSender, connection3, action, request, options, handler, localNode);

        try {
            senderLatch.get().await(1, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            throw new RuntimeException(e);
        }
        senderLatch.set(new CountDownLatch(1));

        assertNull("DLS transient should NOT be set for non-ClusterSearchShardsResponse", dlsTransient.get());
        assertNull("FLS transient should NOT be set for non-ClusterSearchShardsResponse", flsTransient.get());
        assertNull("Masked field transient should NOT be set for non-ClusterSearchShardsResponse", maskedTransient.get());
    }

    /**
     * Property-based style test: For random combinations of DLS/FLS/masked-field response headers,
     * verify transient propagation for ClusterSearchShardsResponse.
     *
     * Generates all 7 non-empty subsets of {DLS, FLS, MaskedField} and verifies that
     * each present header results in the corresponding transient being set, and each
     * absent header results in no transient.
     *
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testPreservation_RandomDlsFlsMaskedCombinations_ClusterSearchShardsResponse() {
        final String dlsValue = "{\"term\":{\"dept\":\"eng\"}}";
        final String flsValue = "name,email,role";
        final String maskedValue = "ssn,phone";

        // Test all 8 combinations (including empty set) of {DLS, FLS, MaskedField}
        for (int combo = 0; combo < 8; combo++) {
            final boolean includeDls = (combo & 1) != 0;
            final boolean includeFls = (combo & 2) != 0;
            final boolean includeMasked = (combo & 4) != 0;

            final AtomicReference<String> dlsTransient = new AtomicReference<>();
            final AtomicReference<String> flsTransient = new AtomicReference<>();
            final AtomicReference<String> maskedTransient = new AtomicReference<>();

            AsyncSender comboSender = new AsyncSender() {
                @Override
                public <T extends TransportResponse> void sendRequest(
                    Connection connection,
                    String action,
                    TransportRequest request,
                    TransportRequestOptions options,
                    TransportResponseHandler<T> handler
                ) {
                    if (includeDls) {
                        threadPool.getThreadContext().addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER, dlsValue);
                    }
                    if (includeFls) {
                        threadPool.getThreadContext().addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER, flsValue);
                    }
                    if (includeMasked) {
                        threadPool.getThreadContext()
                            .addResponseHeader(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER, maskedValue);
                    }

                    ClusterSearchShardsResponse shardsResponse = new ClusterSearchShardsResponse(null, null, null);
                    handler.handleResponse((T) shardsResponse);

                    dlsTransient.set(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_CCS));
                    flsTransient.set(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_CCS));
                    maskedTransient.set(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_CCS));

                    senderLatch.get().countDown();
                }
            };

            securityInterceptor.sendRequestDecorate(comboSender, connection3, action, request, options, handler, localNode);

            try {
                senderLatch.get().await(1, TimeUnit.SECONDS);
            } catch (final InterruptedException e) {
                throw new RuntimeException(e);
            }
            senderLatch.set(new CountDownLatch(1));

            String comboDesc = String.format("combo=%d (DLS=%b, FLS=%b, Masked=%b)", combo, includeDls, includeFls, includeMasked);

            if (includeDls) {
                assertNotNull("DLS transient should be set for " + comboDesc, dlsTransient.get());
                assertThat("DLS value mismatch for " + comboDesc, dlsTransient.get(), is(dlsValue));
            } else {
                assertNull("DLS transient should NOT be set for " + comboDesc, dlsTransient.get());
            }

            if (includeFls) {
                assertNotNull("FLS transient should be set for " + comboDesc, flsTransient.get());
                assertThat("FLS value mismatch for " + comboDesc, flsTransient.get(), is(flsValue));
            } else {
                assertNull("FLS transient should NOT be set for " + comboDesc, flsTransient.get());
            }

            if (includeMasked) {
                assertNotNull("Masked transient should be set for " + comboDesc, maskedTransient.get());
                assertThat("Masked value mismatch for " + comboDesc, maskedTransient.get(), is(maskedValue));
            } else {
                assertNull("Masked transient should NOT be set for " + comboDesc, maskedTransient.get());
            }
        }
    }

    /**
     * Property-based style test: Generate random TransportException instances and verify
     * handleException() restores context and delegates to inner handler for each.
     *
     * Tests with various exception messages and causes to ensure robust exception handling.
     *
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void testPreservation_RandomTransportExceptions_HandleExceptionRestoresAndDelegates() {
        List<TransportException> exceptions = Arrays.asList(
            new TransportException("simple message"),
            new TransportException("message with special chars: <>&\"'"),
            new TransportException((String) null),
            new TransportException("caused exception", new RuntimeException("root cause")),
            new TransportException(new IllegalStateException("state error")),
            new TransportException("unicode: \u00e9\u00e8\u00ea\u00eb"),
            new TransportException("long message " + "x".repeat(1000)),
            new TransportException("empty cause", null)
        );

        for (int i = 0; i < exceptions.size(); i++) {
            final TransportException testException = exceptions.get(i);
            final int testIndex = i;
            final AtomicReference<TransportException> capturedException = new AtomicReference<>();
            final AtomicReference<User> userAfterRestore = new AtomicReference<>();

            TransportResponseHandler<TransportResponse> capturingHandler = new TransportResponseHandler<TransportResponse>() {
                @Override
                public TransportResponse read(org.opensearch.core.common.io.stream.StreamInput in) {
                    return null;
                }

                @Override
                public void handleResponse(TransportResponse response) {}

                @Override
                public void handleException(TransportException exp) {
                    capturedException.set(exp);
                    userAfterRestore.set(threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER));
                }

                @Override
                public String executor() {
                    return "same";
                }
            };

            AsyncSender exceptionSender = new AsyncSender() {
                @Override
                public <T extends TransportResponse> void sendRequest(
                    Connection connection,
                    String action,
                    TransportRequest request,
                    TransportRequestOptions options,
                    TransportResponseHandler<T> handler
                ) {
                    handler.handleException(testException);
                    senderLatch.get().countDown();
                }
            };

            securityInterceptor.sendRequestDecorate(exceptionSender, connection3, action, request, options, capturingHandler, localNode);

            try {
                senderLatch.get().await(1, TimeUnit.SECONDS);
            } catch (final InterruptedException e) {
                throw new RuntimeException(e);
            }
            senderLatch.set(new CountDownLatch(1));

            String desc = "exception[" + testIndex + "]";
            assertNotNull("Exception should be propagated for " + desc, capturedException.get());
            assertThat("Same exception instance should be propagated for " + desc, capturedException.get(), is(testException));
            assertNotNull("User transient should be restored for " + desc, userAfterRestore.get());
            assertThat("User should match original for " + desc, userAfterRestore.get(), is(user));
        }
    }

}
