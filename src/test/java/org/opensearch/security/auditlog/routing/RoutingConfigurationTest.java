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

package org.opensearch.security.auditlog.routing;

import java.util.List;
import java.util.Objects;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.config.ThreadPoolConfig;
import org.opensearch.security.auditlog.helper.MockAuditMessageFactory;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.sink.AuditLogSink;
import org.opensearch.security.auditlog.sink.DebugSink;
import org.opensearch.security.auditlog.sink.ExternalOpenSearchSink;
import org.opensearch.security.auditlog.sink.InternalOpenSearchSink;
import org.opensearch.security.test.helper.file.FileHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class RoutingConfigurationTest extends AbstractAuditlogiUnitTest {

    @Test
    public void testValidConfiguration() throws Exception {
        Settings settings = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_valid.yml"))
            .build();
        AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
        // default
        assertThat(router.defaultSink.getName(), is("default"));
        assertThat(router.defaultSink.getClass(), is(ExternalOpenSearchSink.class));
        // test category sinks
        List<AuditLogSink> sinks = router.categorySinks.get(AuditCategory.MISSING_PRIVILEGES);
        Assert.assertNotNull(sinks);
        // 3, since we include default as well
        assertThat(sinks.size(), is(3));
        assertThat(sinks.get(0).getName(), is("endpoint1"));
        assertThat(sinks.get(0).getClass(), is(InternalOpenSearchSink.class));
        assertThat(sinks.get(1).getName(), is("endpoint2"));
        assertThat(sinks.get(1).getClass(), is(ExternalOpenSearchSink.class));
        assertThat(sinks.get(2).getName(), is("default"));
        assertThat(sinks.get(2).getClass(), is(ExternalOpenSearchSink.class));
        sinks = router.categorySinks.get(AuditCategory.COMPLIANCE_DOC_READ);
        // 1, since we do not include default
        assertThat(sinks.size(), is(1));
        assertThat(sinks.get(0).getName(), is("endpoint3"));
        assertThat(sinks.get(0).getClass(), is(DebugSink.class));
    }

    @Test
    public void testNoDefaultSink() throws Exception {
        Settings settings = Settings.builder()
            .loadFromPath(
                Objects.requireNonNull(
                    FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_no_default.yml")
                )
            )
            .build();
        AuditMessageRouter router = new AuditMessageRouter(settings, null, null, null);
        // no default sink, audit log not enabled
        assertThat(router.isEnabled(), is(false));
        assertThat(router.defaultSink, is(nullValue()));
        assertThat(router.categorySinks, is(nullValue()));
        // make sure no exception is thrown
        router.route(MockAuditMessageFactory.validAuditMessage());
    }

    @Test
    public void testMissingEndpoints() throws Exception {
        Settings settings = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_wrong_endpoint_names.yml"))
            .build();
        AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
        // fallback to debug sink if no default is given
        assertThat(router.defaultSink.getClass(), is(InternalOpenSearchSink.class));
        // missing configuration for endpoint2 / External ES. Fallback to
        // localhost
        List<AuditLogSink> sinks = router.categorySinks.get(AuditCategory.MISSING_PRIVILEGES);
        // 2 valid endpoints
        assertThat(sinks.size(), is(2));
        assertThat(sinks.get(0).getName(), is("endpoint1"));
        assertThat(sinks.get(0).getClass(), is(InternalOpenSearchSink.class));
        assertThat(sinks.get(1).getName(), is("endpoint3"));
        assertThat(sinks.get(1).getClass(), is(DebugSink.class));
        sinks = router.categorySinks.get(AuditCategory.COMPLIANCE_DOC_WRITE);
        assertThat(sinks.size(), is(1));
        assertThat(sinks.get(0).getName(), is("default"));
        assertThat(sinks.get(0).getClass(), is(InternalOpenSearchSink.class));
        // no valid end points for category, must use default
        Assert.assertNull(router.categorySinks.get(AuditCategory.COMPLIANCE_DOC_READ));
    }

    @Test
    public void testWrongCategories() throws Exception {
        Settings settings = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_wrong_categories.yml"))
            .build();
        AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
        // no default sink, we fall back to debug sink
        assertThat(router.defaultSink.getClass(), is(DebugSink.class));

        List<AuditLogSink> sinks = router.categorySinks.get(AuditCategory.MISSING_PRIVILEGES);
        // 3, since default is not valid but replaced with Debug
        assertThat(sinks.size(), is(3));
        assertThat(sinks.get(0).getName(), is("default"));
        assertThat(sinks.get(0).getClass(), is(DebugSink.class));
        assertThat(sinks.get(1).getName(), is("endpoint1"));
        assertThat(sinks.get(1).getClass(), is(InternalOpenSearchSink.class));
        assertThat(sinks.get(2).getName(), is("endpoint2"));
        assertThat(sinks.get(2).getClass(), is(ExternalOpenSearchSink.class));

        sinks = router.categorySinks.get(AuditCategory.GRANTED_PRIVILEGES);
        assertThat(sinks.size(), is(3));
        assertThat(sinks.get(0).getName(), is("endpoint1"));
        assertThat(sinks.get(0).getClass(), is(InternalOpenSearchSink.class));
        assertThat(sinks.get(1).getName(), is("endpoint3"));
        assertThat(sinks.get(1).getClass(), is(DebugSink.class));
        assertThat(sinks.get(2).getName(), is("default"));
        assertThat(sinks.get(2).getClass(), is(DebugSink.class));

        sinks = router.categorySinks.get(AuditCategory.AUTHENTICATED);
        assertThat(sinks.size(), is(1));
        assertThat(sinks.get(0).getName(), is("endpoint1"));
        assertThat(sinks.get(0).getClass(), is(InternalOpenSearchSink.class));

        // bad headers has no valid endpoint, so we use default
        Assert.assertNull(router.categorySinks.get(AuditCategory.BAD_HEADERS));

        // failed login has no endpoint configuration, so we use default
        Assert.assertNull(router.categorySinks.get(AuditCategory.FAILED_LOGIN));

    }

    @Test
    public void testWrongEndpointTypes() throws Exception {
        Settings settings = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_wrong_endpoint_types.yml"))
            .build();
        AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
        // debug sink not valid, fallback to debug
        assertThat(router.defaultSink.getClass(), is(DebugSink.class));

        List<AuditLogSink> sinks = router.categorySinks.get(AuditCategory.MISSING_PRIVILEGES);
        // 2 valid endpoints in config, default falls back to debug
        assertThat(sinks.size(), is(3));
        assertThat(sinks.get(0).getName(), is("endpoint2"));
        assertThat(sinks.get(0).getClass(), is(ExternalOpenSearchSink.class));
        assertThat(sinks.get(1).getName(), is("endpoint3"));
        assertThat(sinks.get(1).getClass(), is(DebugSink.class));
        assertThat(sinks.get(2).getName(), is("default"));
        assertThat(sinks.get(2).getClass(), is(DebugSink.class));

        sinks = router.categorySinks.get(AuditCategory.COMPLIANCE_DOC_WRITE);
        assertThat(sinks.size(), is(1));
        assertThat(sinks.get(0).getName(), is("default"));
        assertThat(sinks.get(0).getClass(), is(DebugSink.class));

        // no valid endpoints for category, must fallback to default
        Assert.assertNull(router.categorySinks.get(AuditCategory.COMPLIANCE_DOC_READ));
    }

    @Test
    public void testNoMultipleEndpointsConfiguration() throws Exception {
        Settings settings = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/sink/configuration_no_multiple_endpoints.yml"))
            .build();
        AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
        ThreadPoolConfig config = router.storagePool.getConfig();
        assertThat(config.getThreadPoolSize(), is(5));
        assertThat(config.getThreadPoolMaxQueueLen(), is(200000));
    }
}
