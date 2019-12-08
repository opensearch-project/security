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

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.auditlog.AbstractAuditlogiUnitTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.helper.FailingSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.helper.LoggingSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.helper.MockAuditMessageFactory;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage.Category;
import com.amazon.opendistroforelasticsearch.security.auditlog.routing.AuditMessageRouter;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.AuditLogSink;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;

public class FallbackTest extends AbstractAuditlogiUnitTest {

	@Test
	public void testFallback() throws Exception {
		Settings.Builder settingsBuilder = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/fallback.yml"));

		Settings settings = settingsBuilder.put("path.home", ".").put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE").put("opendistro_security.audit.threadpool.size", 0).build();

		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);

		AuditMessage msg = MockAuditMessageFactory.validAuditMessage(Category.MISSING_PRIVILEGES);
		router.route(msg);

		// endpoint 1 is failing, endoint2 and default work
		List<AuditLogSink> sinks = router.categorySinks.get(Category.MISSING_PRIVILEGES);
		Assert.assertEquals(3, sinks.size());
		// this sink has failed, message must be logged to fallback sink
		AuditLogSink sink = sinks.get(0);
		Assert.assertEquals("endpoint1", sink.getName());
		Assert.assertEquals(FailingSink.class, sink.getClass());
		sink = sink.getFallbackSink();
		Assert.assertEquals("fallback", sink.getName());
		Assert.assertEquals(LoggingSink.class, sink.getClass());
		LoggingSink loggingSkin = (LoggingSink) sink;
		Assert.assertEquals(msg, loggingSkin.messages.get(0));
		// this sink succeeds
		sink = sinks.get(1);
		Assert.assertEquals("endpoint2", sink.getName());
		Assert.assertEquals(LoggingSink.class, sink.getClass());
		loggingSkin = (LoggingSink) sink;
		Assert.assertEquals(msg, loggingSkin.messages.get(0));
		// default sink also succeeds
		sink = sinks.get(2);
		Assert.assertEquals("default", sink.getName());
		Assert.assertEquals(LoggingSink.class, sink.getClass());
		loggingSkin = (LoggingSink) sink;
		Assert.assertEquals(msg, loggingSkin.messages.get(0));

		// has only one end point which fails
		router = createMessageRouterComplianceEnabled(settings);
		msg = MockAuditMessageFactory.validAuditMessage(Category.COMPLIANCE_DOC_READ);
		router.route(msg);
		sinks = router.categorySinks.get(Category.COMPLIANCE_DOC_READ);
		sink = sinks.get(0);
		Assert.assertEquals("endpoint3", sink.getName());
		Assert.assertEquals(FailingSink.class, sink.getClass());
		sink = sink.getFallbackSink();
		Assert.assertEquals("fallback", sink.getName());
		Assert.assertEquals(LoggingSink.class, sink.getClass());
		loggingSkin = (LoggingSink) sink;
		Assert.assertEquals(msg, loggingSkin.messages.get(0));

		// has only default which succeeds
		router = createMessageRouterComplianceEnabled(settings);
		msg = MockAuditMessageFactory.validAuditMessage(Category.COMPLIANCE_DOC_WRITE);
		router.route(msg);
		sinks = router.categorySinks.get(Category.COMPLIANCE_DOC_WRITE);
		sink = sinks.get(0);
		Assert.assertEquals("default", sink.getName());
		Assert.assertEquals(LoggingSink.class, sink.getClass());
		loggingSkin = (LoggingSink) sink;
		Assert.assertEquals(1, loggingSkin.messages.size());
		Assert.assertEquals(msg, loggingSkin.messages.get(0));
		// fallback must be empty
		sink = sink.getFallbackSink();
		Assert.assertEquals("fallback", sink.getName());
		Assert.assertEquals(LoggingSink.class, sink.getClass());
		loggingSkin = (LoggingSink) sink;
		Assert.assertEquals(0, loggingSkin.messages.size());

		// test non configured categories, must be logged to default only
		router = createMessageRouterComplianceEnabled(settings);
		msg = MockAuditMessageFactory.validAuditMessage(Category.FAILED_LOGIN);
		router.route(msg);
		sinks = router.categorySinks.get(Category.FAILED_LOGIN);
		sink = sinks.get(0);
		Assert.assertEquals("default", sink.getName());
		Assert.assertEquals(LoggingSink.class, sink.getClass());
		loggingSkin = (LoggingSink) sink;
		Assert.assertEquals(1, loggingSkin.messages.size());
		Assert.assertEquals(msg, loggingSkin.messages.get(0));
		// all others must be empty
		assertLoggingSinksEmpty(router, Category.FAILED_LOGIN);

	}

	private void assertLoggingSinksEmpty(AuditMessageRouter router, Category exclude) {
		// get all sinks
		List<AuditLogSink> allSinks = router.categorySinks.values().stream().flatMap(Collection::stream).collect(Collectors.toList());
		allSinks = allSinks.stream().filter(sink -> (sink instanceof LoggingSink)).collect(Collectors.toList());
		allSinks.removeAll(Collections.singleton(router.defaultSink));
		allSinks.removeAll(router.categorySinks.get(exclude));
		for(AuditLogSink sink : allSinks) {
			LoggingSink loggingSink = (LoggingSink)sink;
			Assert.assertEquals(0, loggingSink.messages.size());
		}
	}

}
