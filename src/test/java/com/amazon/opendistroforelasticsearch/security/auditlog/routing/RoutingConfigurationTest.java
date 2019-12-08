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

package com.amazon.opendistroforelasticsearch.security.auditlog.routing;

import java.util.List;

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.auditlog.AbstractAuditlogiUnitTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.helper.MockAuditMessageFactory;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage.Category;
import com.amazon.opendistroforelasticsearch.security.auditlog.routing.AuditMessageRouter;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.AuditLogSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.DebugSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.ExternalESSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.InternalESSink;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;

public class RoutingConfigurationTest extends AbstractAuditlogiUnitTest{

	@Test
	public void testValidConfiguration() throws Exception {
		Settings settings = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_valid.yml")).build();
		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
		// default
		Assert.assertEquals("default", router.defaultSink.getName());
		Assert.assertEquals(ExternalESSink.class, router.defaultSink.getClass());
		// test category sinks
		List<AuditLogSink> sinks = router.categorySinks.get(AuditMessage.Category.MISSING_PRIVILEGES);
		Assert.assertNotNull(sinks);
		// 3, since we include default as well
		Assert.assertEquals(3, sinks.size());
		Assert.assertEquals("endpoint1", sinks.get(0).getName());
		Assert.assertEquals(InternalESSink.class, sinks.get(0).getClass());
		Assert.assertEquals("endpoint2", sinks.get(1).getName());
		Assert.assertEquals(ExternalESSink.class, sinks.get(1).getClass());
		Assert.assertEquals("default", sinks.get(2).getName());
		Assert.assertEquals(ExternalESSink.class, sinks.get(2).getClass());
		sinks = router.categorySinks.get(AuditMessage.Category.COMPLIANCE_DOC_READ);
		// 1, since we do not include default
		Assert.assertEquals(1, sinks.size());
		Assert.assertEquals("endpoint3", sinks.get(0).getName());
		Assert.assertEquals(DebugSink.class, sinks.get(0).getClass());
	}

	@Test
	public void testNoDefaultSink() throws Exception {
		Settings settings = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_no_default.yml")).build();
		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
		// no default sink, audit log not enabled
		Assert.assertEquals(false, router.isEnabled());
		Assert.assertEquals(null, router.defaultSink);
		Assert.assertEquals(0, router.categorySinks.size());
		// make sure no exception is thrown
		router.route(MockAuditMessageFactory.validAuditMessage());
	}

	@Test
	public void testMissingEndpoints() throws Exception {
		Settings settings = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_wrong_endpoint_names.yml")).build();
		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
		// fallback to debug sink if no default is given
		Assert.assertEquals(InternalESSink.class, router.defaultSink.getClass());
		// missing configuration for endpoint2 / External ES. Fallback to
		// localhost
		List<AuditLogSink> sinks = router.categorySinks.get(AuditMessage.Category.MISSING_PRIVILEGES);
		// 2 valid endpoints
		Assert.assertEquals(2, sinks.size());
		Assert.assertEquals("endpoint1", sinks.get(0).getName());
		Assert.assertEquals(InternalESSink.class, sinks.get(0).getClass());
		Assert.assertEquals("endpoint3", sinks.get(1).getName());
		Assert.assertEquals(DebugSink.class, sinks.get(1).getClass());
		sinks = router.categorySinks.get(AuditMessage.Category.COMPLIANCE_DOC_WRITE);
		Assert.assertEquals(1, sinks.size());
		Assert.assertEquals("default", sinks.get(0).getName());
		Assert.assertEquals(InternalESSink.class, sinks.get(0).getClass());
		// no valid end points for category, must use default
		sinks = router.categorySinks.get(AuditMessage.Category.COMPLIANCE_DOC_READ);
		Assert.assertEquals("default", sinks.get(0).getName());
		Assert.assertEquals(InternalESSink.class, sinks.get(0).getClass());
	}

	@Test
	public void testWrongCategories() throws Exception {
		Settings settings = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_wrong_categories.yml")).build();
		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
		// no default sink, we fall back to debug sink
		Assert.assertEquals(DebugSink.class, router.defaultSink.getClass());

		List<AuditLogSink> sinks = router.categorySinks.get(AuditMessage.Category.MISSING_PRIVILEGES);
		// 3, since default is not valid but replaced with Debug
		Assert.assertEquals(3, sinks.size());
		Assert.assertEquals("default", sinks.get(0).getName());
		Assert.assertEquals(DebugSink.class, sinks.get(0).getClass());
		Assert.assertEquals("endpoint1", sinks.get(1).getName());
		Assert.assertEquals(InternalESSink.class, sinks.get(1).getClass());
		Assert.assertEquals("endpoint2", sinks.get(2).getName());
		Assert.assertEquals(ExternalESSink.class, sinks.get(2).getClass());

		sinks = router.categorySinks.get(AuditMessage.Category.GRANTED_PRIVILEGES);
		Assert.assertEquals(3, sinks.size());
		Assert.assertEquals("endpoint1", sinks.get(0).getName());
		Assert.assertEquals(InternalESSink.class, sinks.get(0).getClass());
		Assert.assertEquals("endpoint3", sinks.get(1).getName());
		Assert.assertEquals(DebugSink.class, sinks.get(1).getClass());
		Assert.assertEquals("default", sinks.get(2).getName());
		Assert.assertEquals(DebugSink.class, sinks.get(2).getClass());

		sinks = router.categorySinks.get(AuditMessage.Category.AUTHENTICATED);
		Assert.assertEquals(1, sinks.size());
		Assert.assertEquals("endpoint1", sinks.get(0).getName());
		Assert.assertEquals(InternalESSink.class, sinks.get(0).getClass());

		// bad headers has no valid endpoint, so we use default
		Assert.assertEquals("default", router.categorySinks.get(AuditMessage.Category.BAD_HEADERS).get(0).getName());
		Assert.assertEquals(DebugSink.class, router.categorySinks.get(AuditMessage.Category.BAD_HEADERS).get(0).getClass());

		// failed login has no endpoint configuration, so we use default
		Assert.assertEquals("default", router.categorySinks.get(AuditMessage.Category.FAILED_LOGIN).get(0).getName());
		Assert.assertEquals(DebugSink.class, router.categorySinks.get(AuditMessage.Category.FAILED_LOGIN).get(0).getClass());

	}

	@Test
	public void testWrongEndpointTypes() throws Exception {
		Settings settings = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_wrong_endpoint_types.yml")).build();
		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
		// debug sink not valid, fallback to debug
		Assert.assertEquals(DebugSink.class, router.defaultSink.getClass());

		List<AuditLogSink> sinks = router.categorySinks.get(AuditMessage.Category.MISSING_PRIVILEGES);
		// 2 valid endpoints in config, default falls back to debug
		Assert.assertEquals(3, sinks.size());
		Assert.assertEquals("endpoint2", sinks.get(0).getName());
		Assert.assertEquals(ExternalESSink.class, sinks.get(0).getClass());
		Assert.assertEquals("endpoint3", sinks.get(1).getName());
		Assert.assertEquals(DebugSink.class, sinks.get(1).getClass());
		Assert.assertEquals("default", sinks.get(2).getName());
		Assert.assertEquals(DebugSink.class, sinks.get(2).getClass());

		sinks = router.categorySinks.get(AuditMessage.Category.COMPLIANCE_DOC_WRITE);
		Assert.assertEquals(1, sinks.size());
		Assert.assertEquals("default", sinks.get(0).getName());
		Assert.assertEquals(DebugSink.class, sinks.get(0).getClass());

		// no valid endpoints for category, must fallback to default
		sinks = router.categorySinks.get(AuditMessage.Category.COMPLIANCE_DOC_READ);
		Assert.assertEquals("default", sinks.get(0).getName());
		Assert.assertEquals(DebugSink.class, sinks.get(0).getClass());
	}
}
