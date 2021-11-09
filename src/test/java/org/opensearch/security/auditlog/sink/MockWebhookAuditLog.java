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

package org.opensearch.security.auditlog.sink;

import org.opensearch.common.settings.Settings;

public class MockWebhookAuditLog extends WebhookSink {

	public String payload = null;
	public String url = null;

	public MockWebhookAuditLog(Settings settings, String settingsPrefix, AuditLogSink fallback) throws Exception {
		super("test", settings, settingsPrefix, null, fallback);
	}

	@Override
	protected boolean doPost(String url, String payload) {
		this.payload = payload;
		return true;
	}


	@Override
	protected boolean doGet(String url) {
		this.url = url;
		return true;
	}
}
