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

package org.opensearch.security.auditlog.impl;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.Settings.Builder;
import org.junit.Test;

import org.opensearch.security.auditlog.helper.MyOwnAuditLog;
import org.opensearch.security.auditlog.sink.AuditLogSink;
import org.opensearch.security.auditlog.sink.DebugSink;
import org.opensearch.security.auditlog.sink.ExternalOpenSearchSink;
import org.opensearch.security.auditlog.sink.InternalOpenSearchSink;

public class DelegateTest {
	@Test
	public void auditLogTypeTest() throws Exception{
		testAuditType("DeBUg", DebugSink.class);
		testAuditType("intERnal_OpenSearch", InternalOpenSearchSink.class);
		testAuditType("EXTERnal_OpenSearch", ExternalOpenSearchSink.class);
		testAuditType("org.opensearch.security.auditlog.sink.MyOwnAuditLog", MyOwnAuditLog.class);
		testAuditType("org.opensearch.security.auditlog.sink.MyOwnAuditLog", null);
		testAuditType("idonotexist", null);
	}

	private void testAuditType(String type, Class<? extends AuditLogSink> expectedClass) throws Exception {
		Builder settingsBuilder  = Settings.builder();
		settingsBuilder.put("opendistro_security.audit.type", type);
		settingsBuilder.put("path.home", ".");
		AuditLogImpl auditLog = new AuditLogImpl(settingsBuilder.build(), null, null, null, null, null);
		auditLog.close();
//		if (expectedClass != null) {
//		    Assert.assertNotNull("delegate is null for type: "+type,auditLog.delegate);
//			Assert.assertEquals(expectedClass, auditLog.delegate.getClass());
//		} else {
//			Assert.assertNull(auditLog.delegate);
//		}

	}
}
