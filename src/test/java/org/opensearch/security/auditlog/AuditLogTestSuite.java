/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	KafkaSinkTest.class
})
public class AuditLogTestSuite {

}
