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

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.auditlog.AbstractAuditlogiUnitTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.routing.AuditMessageRouter;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;

public class ThreadPoolSettingsTest extends AbstractAuditlogiUnitTest {

	@Test
	public void testNoMultipleEndpointsConfiguration() throws Exception {
		Settings settings = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/sink/configuration_no_multiple_endpoints.yml")).build();
		AuditMessageRouter router = createMessageRouterComplianceEnabled(settings);
		Assert.assertEquals(5, router.storagePool.threadPoolSize);
		Assert.assertEquals(200000, router.storagePool.threadPoolMaxQueueLen);
	}
}
