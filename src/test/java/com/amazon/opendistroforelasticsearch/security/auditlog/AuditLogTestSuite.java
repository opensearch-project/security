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

package com.amazon.opendistroforelasticsearch.security.auditlog;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import com.amazon.opendistroforelasticsearch.security.auditlog.compliance.ComplianceAuditlogTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.compliance.RestApiComplianceAuditlogTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditlogTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.DelegateTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.DisabledCategoriesTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.IgnoreAuditUsersTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.TracingTests;
import com.amazon.opendistroforelasticsearch.security.auditlog.integration.BasicAuditlogTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.integration.SSLAuditlogTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.routing.FallbackTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.routing.RouterTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.routing.RoutingConfigurationTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.routing.ThreadPoolSettingsTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.KafkaSinkTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.SinkProviderTLSTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.SinkProviderTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.WebhookAuditLogTest;

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
	ThreadPoolSettingsTest.class,
	SinkProviderTest.class,
	SinkProviderTLSTest.class,
	WebhookAuditLogTest.class,
	KafkaSinkTest.class
})
public class AuditLogTestSuite {

}
