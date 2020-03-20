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

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.auditlog.AbstractAuditlogiUnitTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.helper.LoggingSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.helper.MockAuditMessageFactory;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage.Category;
import com.amazon.opendistroforelasticsearch.security.auditlog.routing.AuditMessageRouter;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.AuditLogSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.DebugSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.ExternalESSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.InternalESSink;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;

public class RouterTest extends AbstractAuditlogiUnitTest{


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
    public void testMessageRouting() throws Exception {

		Settings.Builder settingsBuilder = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/routing.yml"));

		Settings settings = settingsBuilder
    			.put("path.home", ".")
    			.put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .build();

		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
        AuditMessage msg = MockAuditMessageFactory.validAuditMessage(Category.MISSING_PRIVILEGES);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, Category.MISSING_PRIVILEGES, "endpoint1", "endpoint2", "default");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(Category.COMPLIANCE_DOC_READ);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, Category.COMPLIANCE_DOC_READ, "endpoint3");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(Category.COMPLIANCE_DOC_WRITE);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, Category.COMPLIANCE_DOC_WRITE, "default");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(Category.FAILED_LOGIN);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, Category.FAILED_LOGIN, "default");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(Category.GRANTED_PRIVILEGES);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, Category.GRANTED_PRIVILEGES, "default");

    }

    private void testMessageDeliveredForCategory(AuditMessageRouter router, AuditMessage msg, Category categoryToCheck, String ... sinkNames) {
    	Map<Category, List<AuditLogSink>> sinksForCategory = router.categorySinks;
    	for(Category category : Category.values()) {
    		if (category.equals(categoryToCheck)) {
    			List<AuditLogSink> sinks = sinksForCategory.get(category);
    			// each sink must contain our message
    			for(AuditLogSink sink : sinks) {
    				LoggingSink logSink = (LoggingSink)sink;
    				Assert.assertEquals(1, logSink.messages.size());
    				Assert.assertEquals(msg, logSink.messages.get(0));
    				Assert.assertTrue(logSink.sb.length() > 0);
    				Assert.assertTrue(Arrays.stream(sinkNames).anyMatch(sink.getName()::equals));
    			}
    		} else {
    			// make sure sinks are empty for all other categories, exclude default
    			List<AuditLogSink> sinks = sinksForCategory.get(category);
    			for(AuditLogSink sink : sinks) {
    				// default is configured for multiple categories, skip
    				if (sink.getName().equals("default")) {
    					continue;
    				}
    				LoggingSink logSink = (LoggingSink)sink;
    				Assert.assertEquals(0, logSink.messages.size());
    				Assert.assertTrue(logSink.sb.length() == 0);
    			}
    		}
    	}
    }

}
