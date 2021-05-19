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

package org.opensearch.security.auditlog.routing;

import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.helper.LoggingSink;
import org.opensearch.security.auditlog.helper.MockAuditMessageFactory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;


public class PerfTest extends AbstractAuditlogiUnitTest {

	@Test
	@Ignore(value="jvm crash on cci")
	public void testPerf() throws Exception {
		Settings.Builder settingsBuilder = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/perftest.yml"));

		Settings settings = settingsBuilder.put("path.home", ".")
				.put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
				.build();

		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
		int limit = 150000;
		while(limit > 0) {
			AuditMessage msg = MockAuditMessageFactory.validAuditMessage(AuditCategory.MISSING_PRIVILEGES);
			router.route(msg);
			limit--;
		}
		LoggingSink loggingSink = (LoggingSink)router.defaultSink.getFallbackSink();
		int currentSize = loggingSink.messages.size();
		Assert.assertTrue(currentSize > 0);
	}

}
