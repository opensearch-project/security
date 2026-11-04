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

package org.opensearch.security.privileges.actionlevel.legacy;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.junit.After;
import org.junit.Test;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.indices.SystemIndices;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.IndicesRequestResolver;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.actionlevel.legacy.IndexResolverReplacer.Resolved;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecuritySettings;
import org.opensearch.security.user.User;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Checks when the legacy evaluator keeps realtime gets and the request cache for a plugin subject: only when every
 * requested index is one of the plugin's own system indices, not as {@code _all}, and none of them is the security
 * index or a protected index.
 */
public class SystemIndexAccessEvaluatorPluginSubjectTest {

    private static final String PLUGIN = "org.opensearch.security.test.OwnerPlugin";
    private static final String OWN_INDEX = ".owner-index";
    private static final String REGULAR_INDEX = "regular-index";
    private static final String SECURITY_INDEX = ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;
    private static final String GET_ACTION = "indices:data/read/get";

    private final User pluginUser = new User("plugin:" + PLUGIN);
    private final GetRequest getRequest = mock(GetRequest.class);
    private final SearchRequest searchRequest = mock(SearchRequest.class);

    @After
    public void resetSystemIndexRegistry() {
        new SystemIndices(Map.of());
    }

    @Test
    public void ownSystemIndexKeepsRealtimeAndRequestCache() {
        registerPluginIndexPatterns(OWN_INDEX);

        evaluate(evaluator(Settings.EMPTY), resolved(OWN_INDEX));

        verify(getRequest, never()).realtime(anyBoolean());
        verify(searchRequest, never()).requestCache(any());
    }

    @Test
    public void ownAndRegularIndexTurnsOffRealtimeAndRequestCache() {
        registerPluginIndexPatterns(OWN_INDEX);

        evaluate(evaluator(Settings.EMPTY), resolved(OWN_INDEX, REGULAR_INDEX));

        verifyRealtimeAndRequestCacheOff();
    }

    @Test
    public void allIndicesTurnsOffRealtimeAndRequestCache() {
        registerPluginIndexPatterns(OWN_INDEX);
        Resolved all = resolved(Set.of("_all"), OWN_INDEX);

        evaluate(evaluator(Settings.EMPTY), all);

        verifyRealtimeAndRequestCacheOff();
    }

    @Test
    public void securityIndexTurnsOffRealtimeAndRequestCacheEvenIfThePluginRegisteredIt() {
        registerPluginIndexPatterns(SECURITY_INDEX);

        evaluate(evaluator(Settings.EMPTY), resolved(SECURITY_INDEX));

        verifyRealtimeAndRequestCacheOff();
    }

    @Test
    public void protectedOwnSystemIndexTurnsOffRealtimeAndRequestCache() {
        registerPluginIndexPatterns(OWN_INDEX);
        Settings protectedOwnIndex = Settings.builder()
            .put(ConfigConstants.SECURITY_PROTECTED_INDICES_ENABLED_KEY, true)
            .putList(ConfigConstants.SECURITY_PROTECTED_INDICES_KEY, OWN_INDEX)
            .build();

        evaluate(evaluator(protectedOwnIndex), resolved(OWN_INDEX));

        verifyRealtimeAndRequestCacheOff();
    }

    private static void registerPluginIndexPatterns(String... patterns) {
        List<SystemIndexDescriptor> descriptors = Arrays.stream(patterns)
            .map(pattern -> new SystemIndexDescriptor(pattern, "test"))
            .toList();
        new SystemIndices(Map.of(PLUGIN, descriptors));
    }

    private static SystemIndexAccessEvaluator evaluator(Settings additionalSettings) {
        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY, true)
            .put(additionalSettings)
            .build();
        return new SystemIndexAccessEvaluator(
            settings,
            mock(AuditLog.class),
            mock(IndexResolverReplacer.class),
            new ClusterSettings(Settings.EMPTY, Set.of(SecuritySettings.SYSTEM_INDICES_RESTORE_INDICES_SETTING))
        );
    }

    private void evaluate(SystemIndexAccessEvaluator evaluator, Resolved resolved) {
        IndexNameExpressionResolver resolver = new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY));
        PrivilegesEvaluationContext context = new PrivilegesEvaluationContext(
            pluginUser,
            ImmutableSet.of(),
            GET_ACTION,
            getRequest,
            ActionRequestMetadata.empty(),
            null,
            resolver,
            new IndicesRequestResolver(resolver),
            () -> null,
            ActionPrivileges.EMPTY,
            List.of()
        );
        for (var request : List.of(getRequest, searchRequest)) {
            PrivilegesEvaluatorResponse response = evaluator.evaluate(
                request,
                null,
                GET_ACTION,
                resolved,
                context,
                ActionPrivileges.EMPTY,
                pluginUser
            );
            assertThat(response == null || response.isAllowed(), is(true));
        }
    }

    private void verifyRealtimeAndRequestCacheOff() {
        verify(getRequest).realtime(Boolean.FALSE);
        verify(searchRequest).requestCache(Boolean.FALSE);
    }

    private static Resolved resolved(String... indices) {
        return resolved(Set.of(indices), indices);
    }

    private static Resolved resolved(Set<String> originalRequested, String... indices) {
        return new Resolved(
            ImmutableSet.of(),
            ImmutableSet.copyOf(indices),
            ImmutableSet.copyOf(originalRequested),
            ImmutableSet.of(),
            Map.of(),
            IndicesOptions.STRICT_EXPAND_OPEN
        );
    }
}
