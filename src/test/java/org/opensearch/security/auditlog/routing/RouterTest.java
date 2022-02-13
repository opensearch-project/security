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

package org.opensearch.security.auditlog.routing;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.helper.LoggingSink;
import org.opensearch.security.auditlog.helper.MockAuditMessageFactory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.sink.AuditLogSink;
import org.opensearch.security.auditlog.sink.DebugSink;
import org.opensearch.security.auditlog.sink.ExternalOpenSearchSink;
import org.opensearch.security.auditlog.sink.InternalOpenSearchSink;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;

public class RouterTest extends AbstractAuditlogiUnitTest{


	@Test
	public void testValidConfiguration() throws Exception {
		Settings settings = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_valid.yml")).build();
		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
		// default
		Assert.assertEquals("default", router.defaultSink.getName());
		Assert.assertEquals(ExternalOpenSearchSink.class, router.defaultSink.getClass());
		// test category sinks
		List<AuditLogSink> sinks = router.categorySinks.get(AuditCategory.MISSING_PRIVILEGES);
		Assert.assertNotNull(sinks);
		// 3, since we include default as well
		Assert.assertEquals(3, sinks.size());
		Assert.assertEquals("endpoint1", sinks.get(0).getName());
		Assert.assertEquals(InternalOpenSearchSink.class, sinks.get(0).getClass());
		Assert.assertEquals("endpoint2", sinks.get(1).getName());
		Assert.assertEquals(ExternalOpenSearchSink.class, sinks.get(1).getClass());
		Assert.assertEquals("default", sinks.get(2).getName());
		Assert.assertEquals(ExternalOpenSearchSink.class, sinks.get(2).getClass());
		sinks = router.categorySinks.get(AuditCategory.COMPLIANCE_DOC_READ);
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
        AuditMessage msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.MISSING_PRIVILEGES);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, AuditCategory.MISSING_PRIVILEGES, "endpoint1", "endpoint2", "default");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.COMPLIANCE_DOC_READ);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, AuditCategory.COMPLIANCE_DOC_READ, "endpoint3");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.COMPLIANCE_DOC_WRITE);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, AuditCategory.COMPLIANCE_DOC_WRITE, "default");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.FAILED_LOGIN);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, AuditCategory.FAILED_LOGIN, "default");

        router = createMessageRouterComplianceEnabled(settings);
        msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.GRANTED_PRIVILEGES);
        router.route(msg);
        testMessageDeliveredForCategory(router, msg, AuditCategory.GRANTED_PRIVILEGES, "default");

    }

    private void testMessageDeliveredForCategory(AuditMessageRouter router, AuditMessage msg, AuditCategory categoryToCheck, String ... sinkNames) {
    	Map<AuditCategory, List<AuditLogSink>> sinksForCategory = router.categorySinks;
    	for(AuditCategory category : AuditCategory.values()) {
			List<AuditLogSink> sinks = sinksForCategory.get(category);
			if (sinks == null) {
				continue;
			}
    		if (category.equals(categoryToCheck)) {
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
