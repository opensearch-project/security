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
import java.net.UnknownHostException;

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

    private Settings settings;

    private ThreadPool threadPool;

    @Before
    public void setup() {
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
            sslConfig
        );
    }

    private void testSendRequestDecorate(Version remoteNodeVersion) {
        boolean useJDKSerialization = remoteNodeVersion.before(ConfigConstants.FIRST_CUSTOM_SERIALIZATION_SUPPORTED_OS_VERSION);
        ClusterName clusterName = ClusterName.DEFAULT;
        when(clusterService.getClusterName()).thenReturn(clusterName);

        MockTransport transport = new MockTransport();
        TransportService transportService = transport.createTransportService(
            Settings.EMPTY,
            threadPool,
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            boundTransportAddress -> clusterService.state().nodes().get(SecurityInterceptor.class.getSimpleName()),
            null,
            emptySet(),
            NoopTracer.INSTANCE
        );

        // CS-SUPPRESS-SINGLE: RegexpSingleline Extensions manager used for creating a mock
        OpenSearchSecurityPlugin.GuiceHolder guiceHolder = new OpenSearchSecurityPlugin.GuiceHolder(
            mock(RepositoriesService.class),
            transportService,
            mock(IndicesService.class),
            mock(PitService.class),
            mock(ExtensionsManager.class)
        );
        // CS-ENFORCE-SINGLE

        User user = new User("John Doe");
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);

        String action = "testAction";
        TransportRequest request = mock(TransportRequest.class);
        TransportRequestOptions options = mock(TransportRequestOptions.class);
        @SuppressWarnings("unchecked")
        TransportResponseHandler<TransportResponse> handler = mock(TransportResponseHandler.class);

        InetAddress localAddress = null;
        try {
            localAddress = InetAddress.getByName("0.0.0.0");
        } catch (final UnknownHostException uhe) {
            throw new RuntimeException(uhe);
        }

        DiscoveryNode localNode = new DiscoveryNode("local-node", new TransportAddress(localAddress, 1234), Version.CURRENT);
        Connection connection1 = transportService.getConnection(localNode);

        DiscoveryNode otherNode = new DiscoveryNode("remote-node", new TransportAddress(localAddress, 4321), remoteNodeVersion);
        Connection connection2 = transportService.getConnection(otherNode);

        // from thread context inside sendRequestDecorate
        AsyncSender sender = new AsyncSender() {
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
            }
        };
        // isSameNodeRequest = true
        securityInterceptor.sendRequestDecorate(sender, connection1, action, request, options, handler, localNode);

        // from original context
        User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser, user);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);

        // checking thread context inside sendRequestDecorate
        sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                assertEquals(serializedUserHeader, Base64Helper.serializeObject(user, useJDKSerialization));
            }
        };
        // isSameNodeRequest = false
        securityInterceptor.sendRequestDecorate(sender, connection2, action, request, options, handler, localNode);

        // from original context
        User transientUser2 = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser2, user);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);
    }

    @Test
    public void testSendRequestDecorate() {
        testSendRequestDecorate(Version.CURRENT);
    }

    /**
     * Tests the scenario when remote node does not implement custom serialization protocol and uses JDK serialization
     */
    @Test
    public void testSendRequestDecorateWhenRemoteNodeUsesJDKSerde() {
        testSendRequestDecorate(Version.V_2_0_0);
    }

}
