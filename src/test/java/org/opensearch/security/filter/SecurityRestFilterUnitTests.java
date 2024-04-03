package org.opensearch.security.filter;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.bytes.BytesArray;
import org.opensearch.rest.RestStatus;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.util.FakeRestRequest;
import org.opensearch.threadpool.ThreadPool;

import com.google.common.collect.ImmutableMap;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class SecurityRestFilterUnitTests {

    SecurityRestFilter sf;
    RestHandler testRestHandler;

    class TestRestHandler implements RestHandler {

        @Override
        public void handleRequest(RestRequest request, RestChannel channel, NodeClient client) throws Exception {
            channel.sendResponse(new BytesRestResponse(RestStatus.OK, BytesRestResponse.TEXT_CONTENT_TYPE, BytesArray.EMPTY));
        }
    }

    @Before
    public void setUp() throws NoSuchMethodException {
        testRestHandler = new TestRestHandler();

        ThreadPool tp = spy(new ThreadPool(Settings.builder().put("node.name", "mock").build()));
        doReturn(new ThreadContext(Settings.EMPTY)).when(tp).getThreadContext();

        sf = new SecurityRestFilter(
            mock(BackendRegistry.class),
            mock(AuditLog.class),
            tp,
            mock(PrincipalExtractor.class),
            Settings.EMPTY,
            mock(Path.class),
            mock(CompatConfig.class)
        );
    }

    @Ignore
    @Test
    public void testDoesCallDelegateOnSuccessfulAuthorization() throws Exception {
        SecurityRestFilter filterSpy = spy(sf);
        AdminDNs adminDNs = mock(AdminDNs.class);

        RestHandler testRestHandlerSpy = spy(testRestHandler);
        RestHandler wrappedRestHandler = filterSpy.wrap(testRestHandlerSpy, adminDNs);

        doReturn(false).when(filterSpy).userIsSuperAdmin(any(), any());
        // doReturn(true).when(filterSpy).authorizeRequest(any(), any(), any());

        FakeRestRequest fakeRequest = new FakeRestRequest.Builder().withPath("/test")
            .withMethod(RestRequest.Method.POST)
            .withHeaders(ImmutableMap.of("Content-Type", "application/json"))
            .build();

        wrappedRestHandler.handleRequest(fakeRequest, mock(RestChannel.class), mock(NodeClient.class));

        verify(testRestHandlerSpy).handleRequest(any(), any(), any());
    }

    @Ignore
    @Test
    public void testDoesNotCallDelegateOnUnauthorized() throws Exception {
        SecurityRestFilter filterSpy = spy(sf);
        AdminDNs adminDNs = mock(AdminDNs.class);

        RestHandler testRestHandlerSpy = spy(testRestHandler);
        RestHandler wrappedRestHandler = filterSpy.wrap(testRestHandlerSpy, adminDNs);

        doReturn(false).when(filterSpy).userIsSuperAdmin(any(), any());
        // doReturn(false).when(filterSpy).authorizeRequest(any(), any(), any());

        FakeRestRequest fakeRequest = new FakeRestRequest.Builder().withPath("/test")
            .withMethod(RestRequest.Method.POST)
            .withHeaders(ImmutableMap.of("Content-Type", "application/json"))
            .build();

        wrappedRestHandler.handleRequest(fakeRequest, mock(RestChannel.class), mock(NodeClient.class));

        verify(testRestHandlerSpy, never()).handleRequest(any(), any(), any());
    }
}
