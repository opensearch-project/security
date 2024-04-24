/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

// CS-SUPPRESS-SINGLE: RegexpSingleline Extensions manager used for creating a mock
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.Version;
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
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.telemetry.tracing.noop.NoopTracer;
import org.opensearch.test.transport.MockTransport;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Transport.Connection;
import org.opensearch.transport.TransportInterceptor.AsyncSender;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestOptions;
import org.opensearch.transport.TransportResponseHandler;
import org.opensearch.transport.TransportService;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static java.util.Collections.emptySet;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
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

    private AsyncSender sender;
    private AsyncSender serializedSender;
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
            () -> true
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

        // CS-SUPPRESS-SINGLE: RegexpSingleline Extensions manager used for creating a mock
        guiceHolder = new OpenSearchSecurityPlugin.GuiceHolder(
            mock(RepositoriesService.class),
            transportService,
            mock(IndicesService.class),
            mock(PitService.class),
            mock(ExtensionsManager.class)
        );
        // CS-ENFORCE-SINGLE

        // Instantiate objects for tests
        user = new User("John Doe");

        request = mock(TransportRequest.class);
        options = mock(TransportRequestOptions.class);

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

        serializedSender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                assertEquals(serializedUserHeader, Base64Helper.serializeObject(user, true));
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
                assertEquals(transientUser, user);
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
        assertEquals(transientUser, user);
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
        completableRequestDecorate(serializedSender, connection3, action, request, options, handler, localNode);
        // this is a remote request where the transport address is different
        completableRequestDecorate(serializedSender, connection4, action, request, options, handler, localNode);
    }

    @Test
    public void testSendNoOriginNodeCausesSerialization() {

        // this is a request where the local node is null; have to use the remote connection since the serialization will fail
        completableRequestDecorate(serializedSender, connection3, action, request, options, handler, null);
    }

    @Test
    public void testSendNoConnectionShouldThrowNPE() {

        // The completable version swallows the NPE so have to call actual method
        assertThrows(
            java.lang.NullPointerException.class,
            () -> securityInterceptor.sendRequestDecorate(serializedSender, null, action, request, options, handler, localNode)
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
        completableRequestDecorate(serializedSender, connection3, action, request, options, handler, localNode);
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
        completableRequestDecorate(serializedSender, connection3, action, request, options, handler, localNode);
    }

    @Test
    public void testNullHeaderIsIgnored() {

        // Add a null header
        threadPool.getThreadContext().putHeader(null, null);
        threadPool.getThreadContext().putHeader(null, "null");
        // this is a local request
        completableRequestDecorate(sender, connection1, action, request, options, handler, localNode);
        // this is a remote request
        completableRequestDecorate(serializedSender, connection3, action, request, options, handler, localNode);
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
}
