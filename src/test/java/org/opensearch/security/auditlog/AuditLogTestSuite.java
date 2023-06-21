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

package org.opensearch.security.auditlog;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import org.opensearch.security.auditlog.compliance.ComplianceAuditlogTest;
import org.opensearch.security.auditlog.compliance.RestApiComplianceAuditlogTest;
import org.opensearch.security.auditlog.impl.AuditlogTest;
import org.opensearch.security.auditlog.impl.DelegateTest;
import org.opensearch.security.auditlog.impl.DisabledCategoriesTest;
import org.opensearch.security.auditlog.impl.IgnoreAuditUsersTest;
import org.opensearch.security.auditlog.impl.TracingTests;
import org.opensearch.security.auditlog.integration.BasicAuditlogTest;
import org.opensearch.security.auditlog.integration.SSLAuditlogTest;
import org.opensearch.security.auditlog.routing.FallbackTest;
import org.opensearch.security.auditlog.routing.RouterTest;
import org.opensearch.security.auditlog.routing.RoutingConfigurationTest;
import org.opensearch.security.auditlog.sink.KafkaSinkTest;
import org.opensearch.security.auditlog.sink.SinkProviderTLSTest;
import org.opensearch.security.auditlog.sink.SinkProviderTest;
import org.opensearch.security.auditlog.sink.WebhookAuditLogTest;

@RunWith(Suite.class)

@Suite.SuiteClasses({
    ComplianceAuditlogTest.class,
    RestApiComplianceAuditlogTest.class,
    AuditlogTest.class,
    DelegateTest.class,
    DisabledCategoriesTest.class,
    IgnoreAuditUsersTest.class,
    TracingTests.class,
    BasicAuditlogTest.class,
    SSLAuditlogTest.class,
    FallbackTest.class,
    RouterTest.class,
    RoutingConfigurationTest.class,
    SinkProviderTest.class,
    SinkProviderTLSTest.class,
    WebhookAuditLogTest.class,
    KafkaSinkTest.class })
public class AuditLogTestSuite {

}
