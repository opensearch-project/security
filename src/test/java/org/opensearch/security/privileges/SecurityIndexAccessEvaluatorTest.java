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

package org.opensearch.security.privileges;

import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.tasks.Task;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SecurityIndexAccessEvaluatorTest {

    @Mock
    private AuditLog auditLog;
    @Mock
    private IndexResolverReplacer irr;
    @Mock
    private ActionRequest request;
    @Mock
    private Task task;
    @Mock
    private PrivilegesEvaluatorResponse presponse;
    @Mock
    private Logger log;
    @Mock
    private ThreadContext threadContext;

    private SecurityIndexAccessEvaluator evaluator;

    private static final String UNPROTECTED_ACTION = "indices:data/read";
    private static final String PROTECTED_ACTION = "indices:data/write";

    @Before
    public void before() {
        evaluator = new SecurityIndexAccessEvaluator(
            Settings.EMPTY.builder()
                .put("plugins.security.system_indices.indices", ".test")
                .put("plugins.security.system_indices.enabled", true)
                .build(),
            auditLog,
            irr,
            threadContext
        );
        evaluator.log = log;

        when(log.isDebugEnabled()).thenReturn(true);
    }

    @After
    public void after() {
        verifyNoMoreInteractions(auditLog, irr, request, task, presponse, log);
    }

    @Test
    public void actionIsNotProtected_noSystemIndexInvolved() {
        final Resolved resolved = createResolved(".test");

        // Action
        final PrivilegesEvaluatorResponse response = evaluator.evaluate(request, null, UNPROTECTED_ACTION, resolved, presponse);

        verifyNoInteractions(presponse);
        assertThat(response, is(presponse));

        verify(log).isDebugEnabled();
    }

    @Test
    public void disableCacheOrRealtimeOnSystemIndex() {
        final SearchRequest searchRequest = mock(SearchRequest.class);
        final MultiGetRequest realtimeRequest = mock(MultiGetRequest.class);
        final Resolved resolved = createResolved(".test");

        // Action
        evaluator.evaluate(request, null, UNPROTECTED_ACTION, resolved, presponse);
        evaluator.evaluate(searchRequest, null, UNPROTECTED_ACTION, resolved, presponse);
        evaluator.evaluate(realtimeRequest, null, UNPROTECTED_ACTION, resolved, presponse);

        verifyNoInteractions(presponse);
        verify(searchRequest).requestCache(Boolean.FALSE);
        verify(realtimeRequest).realtime(Boolean.FALSE);

        verify(log, times(3)).isDebugEnabled();
        verify(log).debug("Disable search request cache for this request");
        verify(log).debug("Disable realtime for this request");
    }

    @Test
    public void protectedActionLocalAll() {
        final Resolved resolved = Resolved._LOCAL_ALL;

        // Action
        evaluator.evaluate(request, task, PROTECTED_ACTION, resolved, presponse);

        verify(auditLog).logSecurityIndexAttempt(request, PROTECTED_ACTION, task);
        assertThat(presponse.allowed, is(false));
        verify(presponse).markComplete();

        verify(log).isDebugEnabled();
        verify(log).warn("{} for '_all' indices is not allowed for a regular user", "indices:data/write");
    }

    @Test
    public void protectedActionSystemIndex() {
        final Resolved resolved = createResolved(".test", ".opendistro_security");

        // Action
        evaluator.evaluate(request, task, PROTECTED_ACTION, resolved, presponse);

        verify(auditLog).logSecurityIndexAttempt(request, PROTECTED_ACTION, task);
        assertThat(presponse.allowed, is(false));
        verify(presponse).markComplete();

        verify(log).isDebugEnabled();
        verify(log).warn("{} for '{}' index is not allowed for a regular user", "indices:data/write", ".opendistro_security, .test");
    }

    private Resolved createResolved(final String... indexes) {
        return new Resolved(
            ImmutableSet.of(),
            ImmutableSet.copyOf(indexes),
            ImmutableSet.copyOf(indexes),
            ImmutableSet.of(),
            IndicesOptions.STRICT_EXPAND_OPEN
        );
    }
}
