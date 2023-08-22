/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

// CS-SUPPRESS-SINGLE: RegexpSingleline Extensions manager used for creating a mock
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.Version;
import org.opensearch.action.search.PitService;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
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
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.transport.MockTransport;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Transport.Connection;
import org.opensearch.transport.TransportInterceptor.AsyncSender;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestOptions;
import org.opensearch.core.transport.TransportResponse;
import org.opensearch.transport.TransportResponseHandler;
import org.opensearch.transport.TransportService;

import static java.util.Collections.emptySet;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
// CS-ENFORCE-SINGLE

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

    @Test
    public void testSendRequestDecorate() {

        ClusterName clusterName = ClusterName.DEFAULT;
        when(clusterService.getClusterName()).thenReturn(clusterName);

        MockTransport transport = new MockTransport();
        TransportService transportService = transport.createTransportService(
            Settings.EMPTY,
            threadPool,
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            boundTransportAddress -> clusterService.state().nodes().get(SecurityInterceptor.class.getSimpleName()),
            null,
            emptySet()
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

        AsyncSender sender = mock(AsyncSender.class);
        String action = "testAction";
        TransportRequest request = mock(TransportRequest.class);
        TransportRequestOptions options = mock(TransportRequestOptions.class);
        TransportResponseHandler<TransportResponse> handler = mock(TransportResponseHandler.class);

        DiscoveryNode localNode = new DiscoveryNode("local-node", OpenSearchTestCase.buildNewFakeTransportAddress(), Version.CURRENT);
        Connection connection1 = transportService.getConnection(localNode);

        DiscoveryNode otherNode = new DiscoveryNode("local-node", OpenSearchTestCase.buildNewFakeTransportAddress(), Version.CURRENT);
        Connection connection2 = transportService.getConnection(otherNode);

        // isSameNodeRequest = true
        securityInterceptor.sendRequestDecorate(sender, connection1, action, request, options, handler, localNode);
        // from thread context inside sendRequestDecorate
        doAnswer(i -> {
            User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            assertEquals(transientUser, user);
            return null;
        }).when(sender).sendRequest(any(Connection.class), eq(action), eq(request), eq(options), eq(handler));

        // from original context
        User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser, user);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);

        // isSameNodeRequest = false
        securityInterceptor.sendRequestDecorate(sender, connection2, action, request, options, handler, otherNode);
        // checking thread context inside sendRequestDecorate
        doAnswer(i -> {
            String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
            assertEquals(serializedUserHeader, Base64Helper.serializeObject(user));
            return null;
        }).when(sender).sendRequest(any(Connection.class), eq(action), eq(request), eq(options), eq(handler));

        // from original context
        User transientUser2 = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(transientUser2, user);
        assertEquals(threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER), null);

    }

}
