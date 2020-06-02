package com.amazon.opendistroforelasticsearch.security.filter;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.CompatConfig;
import com.amazon.opendistroforelasticsearch.security.configuration.DlsFlsRequestValve;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.google.common.collect.ImmutableSet;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

@RunWith(Parameterized.class)
public class OpenDistroSecurityFilterTest {

    private final Settings settings;
    private final WildcardMatcher expected;

    public OpenDistroSecurityFilterTest(Settings settings, WildcardMatcher expected) {
        this.settings = settings;
        this.expected = expected;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {Settings.EMPTY, WildcardMatcher.NONE},
                {Settings.builder()
                        .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "immutable1", "immutable2")
                        .build(),
                        WildcardMatcher.from(ImmutableSet.of("immutable1", "immutable2"))},
                {Settings.builder()
                        .putList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "immutable1", "immutable2", "immutable2")
                        .build(),
                        WildcardMatcher.from(ImmutableSet.of("immutable1", "immutable2"))},
        });
    }

    @Test
    public void testImmutableIndicesWildcardMatcher() {
        final OpenDistroSecurityFilter filter = new OpenDistroSecurityFilter(
                settings,
                mock(PrivilegesEvaluator.class),
                mock(AdminDNs.class),
                mock(DlsFlsRequestValve.class),
                mock(AuditLog.class),
                mock(ThreadPool.class),
                mock(ClusterService.class),
                mock(CompatConfig.class),
                mock(IndexResolverReplacer.class)
        );
        assertEquals(expected, filter.getImmutableIndicesMatcher());
    }
}
