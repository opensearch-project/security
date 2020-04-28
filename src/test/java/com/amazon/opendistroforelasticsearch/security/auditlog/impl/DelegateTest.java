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

package com.amazon.opendistroforelasticsearch.security.auditlog.impl;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.auditlog.helper.MyOwnAuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditLogImpl;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.AuditLogSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.DebugSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.ExternalESSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.InternalESSink;

public class DelegateTest {
	@Test
	public void auditLogTypeTest() throws Exception{
		testAuditType("DeBUg", DebugSink.class);
		testAuditType("intERnal_Elasticsearch", InternalESSink.class);
		testAuditType("EXTERnal_Elasticsearch", ExternalESSink.class);
		testAuditType("com.amazon.opendistroforelasticsearch.security.auditlog.sink.MyOwnAuditLog", MyOwnAuditLog.class);
		testAuditType("com.amazon.opendistroforelasticsearch.security.auditlog.sink.MyOwnAuditLog", null);
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
