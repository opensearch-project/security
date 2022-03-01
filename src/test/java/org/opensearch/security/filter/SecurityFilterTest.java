/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.filter;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.configuration.DlsFlsRequestValve;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import com.google.common.collect.ImmutableSet;

import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.threadpool.ThreadPool;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@RunWith(Parameterized.class)
public class SecurityFilterTest {

    private final Settings settings;
    private final WildcardMatcher expected;

    public SecurityFilterTest(Settings settings, WildcardMatcher expected) {
        this.settings = settings;
        this.expected = expected;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {Settings.EMPTY, WildcardMatcher.NONE},
                {Settings.builder()
                        .putList(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "immutable1", "immutable2")
                        .build(),
                        WildcardMatcher.from(ImmutableSet.of("immutable1", "immutable2"))},
                {Settings.builder()
                        .putList(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "immutable1", "immutable2", "immutable2")
                        .build(),
                        WildcardMatcher.from(ImmutableSet.of("immutable1", "immutable2"))},
        });
    }

    @Test
    public void testImmutableIndicesWildcardMatcher() {
        final SecurityFilter filter = new SecurityFilter(
                mock(Client.class),
                settings,
                mock(PrivilegesEvaluator.class),
                mock(AdminDNs.class),
                mock(DlsFlsRequestValve.class),
                mock(AuditLog.class),
                mock(ThreadPool.class),
                mock(ClusterService.class),
                mock(CompatConfig.class),
                mock(IndexResolverReplacer.class),
                mock(BackendRegistry.class),
                mock(NamedXContentRegistry.class)
        );
        assertEquals(expected, filter.getImmutableIndicesMatcher());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUnexepectedCausesAreNotSendToCallers() {
        // Setup
        final AuditLog auditLog = mock(AuditLog.class);
        when(auditLog.getComplianceConfig()).thenThrow(new RuntimeException("ABC!"));
        final ActionListener<ActionResponse> listener = mock(ActionListener.class);

        final SecurityFilter filter = new SecurityFilter(
            mock(Client.class),
            settings,
            mock(PrivilegesEvaluator.class),
            mock(AdminDNs.class),
            mock(DlsFlsRequestValve.class),
            auditLog,
            new ThreadPool(Settings.builder().put("node.name",  "mock").build()),
            mock(ClusterService.class),
            mock(CompatConfig.class),
            mock(IndexResolverReplacer.class),
            mock(BackendRegistry.class),
            mock(NamedXContentRegistry.class)
        );

        // Act
        filter.apply(null, null, null, listener, null);

        // Verify
        verify(auditLog).getComplianceConfig(); // Make sure the exception was thrown

        final ArgumentCaptor<OpenSearchSecurityException> cap = ArgumentCaptor.forClass(OpenSearchSecurityException.class);
        verify(listener).onFailure(cap.capture());

        assertNull(cap.getValue().getCause(), "The cause should never be included as it will leak to callers"); 
        assertFalse(cap.getValue().getMessage().contains("ABC!"), "Make sure the cause exception wasn't toStringed in the method");

        verifyNoMoreInteractions(auditLog, listener);
    }
}
