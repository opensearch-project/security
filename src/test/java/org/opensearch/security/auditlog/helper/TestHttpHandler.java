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

package org.opensearch.security.auditlog.helper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.RequestLine;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.util.EntityUtils;

public class TestHttpHandler implements HttpRequestHandler {
	public String method;
	public String uri;
	public String body;

	@Override
	public void handle(HttpRequest request, HttpResponse response, HttpContext context) throws HttpException, IOException {
		RequestLine requestLine = request.getRequestLine();
		this.method = requestLine.getMethod();
		this.uri = requestLine.getUri();

		HttpEntity entity = null;
		if (request instanceof HttpEntityEnclosingRequest) {
			entity = ((HttpEntityEnclosingRequest) request).getEntity();
			body = EntityUtils.toString(entity, StandardCharsets.UTF_8);
		}
	}

	public void reset() {
		this.body = null;
		this.uri = null;
		this.method = null;
	}
}
