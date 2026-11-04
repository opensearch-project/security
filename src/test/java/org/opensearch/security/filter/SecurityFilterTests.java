/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.filter;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.google.common.collect.ImmutableSet;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.action.whoami.WhoAmIAction;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.configuration.DlsFlsRequestValve;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.ResourceAccessEvaluator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@LuceneTestCase.SuppressSysoutChecks(bugUrl = "Parameterized thread pool tests initialize infrastructure that logs during startup")
public class SecurityFilterTests extends LuceneTestCase {

    private final Settings settings;
    private final WildcardMatcher expected;

    public SecurityFilterTests(Settings settings, WildcardMatcher expected) {
        this.settings = settings;
        this.expected = expected;
    }

    @ParametersFactory
    public static Collection<Object[]> data() {
        return Arrays.asList(
            new Object[][] {
                { Settings.EMPTY, WildcardMatcher.NONE },
                {
                    Settings.builder().putList(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "immutable1", "immutable2").build(),
                    WildcardMatcher.from(ImmutableSet.of("immutable1", "immutable2")) },
                {
                    Settings.builder()
                        .putList(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "immutable1", "immutable2", "immutable2")
                        .build(),
                    WildcardMatcher.from(ImmutableSet.of("immutable1", "immutable2")) }, }
        );
    }

    @Test
    public void testImmutableIndicesWildcardMatcher() {
        final SecurityFilter filter = new SecurityFilter(
            settings,
            mock(PrivilegesConfiguration.class),
            mock(AdminDNs.class),
            mock(DlsFlsRequestValve.class),
            mock(AuditLog.class),
            mock(ThreadPool.class),
            mock(ClusterService.class),
            mock(CompatConfig.class),
            mock(XFFResolver.class),
            mock(ResourceAccessEvaluator.class)
        );
        assertThat(expected, equalTo(filter.getImmutableIndicesMatcher()));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUnexepectedCausesAreNotSendToCallers() {
        // Setup
        final AuditLog auditLog = mock(AuditLog.class);
        when(auditLog.getComplianceConfig()).thenThrow(new RuntimeException("ABC!"));
        final ActionListener<ActionResponse> listener = mock(ActionListener.class);
        final ThreadPool threadPool = new ThreadPool(Settings.builder().put("node.name", "mock").build());

        try {
            final SecurityFilter filter = new SecurityFilter(
                settings,
                mock(PrivilegesConfiguration.class),
                mock(AdminDNs.class),
                mock(DlsFlsRequestValve.class),
                auditLog,
                threadPool,
                mock(ClusterService.class),
                mock(CompatConfig.class),
                mock(XFFResolver.class),
                mock(ResourceAccessEvaluator.class)
            );

            // Act
            filter.apply(null, null, null, ActionRequestMetadata.empty(), listener, null);

            // Verify
            verify(auditLog).getComplianceConfig(); // Make sure the exception was thrown

            final ArgumentCaptor<OpenSearchSecurityException> cap = ArgumentCaptor.forClass(OpenSearchSecurityException.class);
            verify(listener).onFailure(cap.capture());

            assertThat("The cause should never be included as it will leak to callers", cap.getValue().getCause(), nullValue());
            assertThat(
                "Make sure the cause exception wasn't toStringed in the method",
                cap.getValue().getMessage(),
                not(containsString("ABC!"))
            );

            verifyNoMoreInteractions(auditLog, listener);
        } finally {
            ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testErrorFromChainKeepsCause() {
        // Setup
        final ActionListener<ActionResponse> listener = mock(ActionListener.class);
        final ThreadPool threadPool = new ThreadPool(Settings.builder().put("node.name", "mock").build());
        final NoSuchMethodError error = new NoSuchMethodError("missing method");
        final ActionFilterChain<ActionRequest, ActionResponse> chain = (task, action, request, l) -> { throw error; };

        try {
            final SecurityFilter filter = new SecurityFilter(
                settings,
                mock(PrivilegesConfiguration.class),
                mock(AdminDNs.class),
                mock(DlsFlsRequestValve.class),
                mock(AuditLog.class),
                threadPool,
                mock(ClusterService.class),
                mock(CompatConfig.class),
                mock(XFFResolver.class),
                mock(ResourceAccessEvaluator.class)
            );

            // Act
            filter.apply(null, WhoAmIAction.NAME, mock(ActionRequest.class), ActionRequestMetadata.empty(), listener, chain);

            // Verify
            final ArgumentCaptor<OpenSearchSecurityException> cap = ArgumentCaptor.forClass(OpenSearchSecurityException.class);
            verify(listener).onFailure(cap.capture());
            assertThat(cap.getValue().status(), equalTo(RestStatus.INTERNAL_SERVER_ERROR));
            assertThat(cap.getValue().getCause(), sameInstance(error));
            verifyNoMoreInteractions(listener);
        } finally {
            ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testErrorFromChainKeepsCauseForAllowedRequestWithUser() {
        // Setup
        final ActionListener<ActionResponse> listener = mock(ActionListener.class);
        final ThreadPool threadPool = new ThreadPool(Settings.builder().put("node.name", "mock").build());
        final NoSuchMethodError error = new NoSuchMethodError("missing method");
        final ActionFilterChain<ActionRequest, ActionResponse> chain = (task, action, request, l) -> { throw error; };

        final PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        final PrivilegesEvaluator evaluator = mock(PrivilegesEvaluator.class);
        when(evaluator.createContext(any(), any(), any(), any(), any())).thenReturn(context);
        when(evaluator.evaluate(context)).thenReturn(PrivilegesEvaluatorResponse.ok());
        final PrivilegesConfiguration privilegesConfiguration = mock(PrivilegesConfiguration.class);
        when(privilegesConfiguration.privilegesEvaluator()).thenReturn(evaluator);
        final DlsFlsRequestValve dlsFlsValve = mock(DlsFlsRequestValve.class);
        when(dlsFlsValve.invoke(any(), any())).thenReturn(true);

        final ThreadContext threadContext = threadPool.getThreadContext();
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, new User("test_user"));
            // Already set, so the filter does not build the user info from the mocked context
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT, "test_user");

            final SecurityFilter filter = new SecurityFilter(
                settings,
                privilegesConfiguration,
                mock(AdminDNs.class),
                dlsFlsValve,
                mock(AuditLog.class),
                threadPool,
                mock(ClusterService.class),
                mock(CompatConfig.class),
                mock(XFFResolver.class),
                mock(ResourceAccessEvaluator.class)
            );

            // Act
            filter.apply(null, "indices:data/read/search", mock(ActionRequest.class), ActionRequestMetadata.empty(), listener, chain);

            // Verify
            verify(evaluator).evaluate(context);
            final ArgumentCaptor<OpenSearchSecurityException> cap = ArgumentCaptor.forClass(OpenSearchSecurityException.class);
            verify(listener).onFailure(cap.capture());
            assertThat(cap.getValue().status(), equalTo(RestStatus.INTERNAL_SERVER_ERROR));
            assertThat(cap.getValue().getCause(), sameInstance(error));
            verifyNoMoreInteractions(listener);
        } finally {
            ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testErrorFromChainKeepsCauseWhenResourceAccessAnswersOnSameThread() {
        // Setup
        final ActionListener<ActionResponse> listener = mock(ActionListener.class);
        final ThreadPool threadPool = new ThreadPool(Settings.builder().put("node.name", "mock").build());
        final NoSuchMethodError error = new NoSuchMethodError("missing method");
        final ActionFilterChain<ActionRequest, ActionResponse> chain = (task, action, request, l) -> { throw error; };
        final ActionRequest request = mock(ActionRequest.class);

        final PrivilegesEvaluator evaluator = mock(PrivilegesEvaluator.class);
        when(evaluator.createContext(any(), any(), any(), any(), any())).thenReturn(mock(PrivilegesEvaluationContext.class));
        final PrivilegesConfiguration privilegesConfiguration = mock(PrivilegesConfiguration.class);
        when(privilegesConfiguration.privilegesEvaluator()).thenReturn(evaluator);

        // Answers on the calling thread, as an admin user's permission check does
        final ResourceAccessEvaluator resourceAccessEvaluator = mock(ResourceAccessEvaluator.class);
        when(resourceAccessEvaluator.evaluableResourceRequest(request)).thenReturn(
            new ResourceAccessEvaluator.ResourceRequest("resource-index", "resource-type", List.of("id-1"))
        );
        doAnswer(invocation -> {
            invocation.<ActionListener<PrivilegesEvaluatorResponse>>getArgument(2).onResponse(PrivilegesEvaluatorResponse.ok());
            return null;
        }).when(resourceAccessEvaluator).evaluateAsync(any(), any(), any());

        final ThreadContext threadContext = threadPool.getThreadContext();
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, new User("test_user"));
            // Already set, so the filter does not build the user info from the mocked context
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT, "test_user");

            final SecurityFilter filter = new SecurityFilter(
                settings,
                privilegesConfiguration,
                mock(AdminDNs.class),
                mock(DlsFlsRequestValve.class),
                mock(AuditLog.class),
                threadPool,
                mock(ClusterService.class),
                mock(CompatConfig.class),
                mock(XFFResolver.class),
                resourceAccessEvaluator
            );

            // Act
            filter.apply(null, "indices:data/read/get", request, ActionRequestMetadata.empty(), listener, chain);

            // Verify
            verify(resourceAccessEvaluator).evaluateAsync(any(), any(), any());
            final ArgumentCaptor<OpenSearchSecurityException> cap = ArgumentCaptor.forClass(OpenSearchSecurityException.class);
            verify(listener).onFailure(cap.capture());
            assertThat(cap.getValue().status(), equalTo(RestStatus.INTERNAL_SERVER_ERROR));
            assertThat(cap.getValue().getCause(), sameInstance(error));
            verifyNoMoreInteractions(listener);
        } finally {
            ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
        }
    }
}
