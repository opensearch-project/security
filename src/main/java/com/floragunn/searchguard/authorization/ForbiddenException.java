/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */
package com.floragunn.searchguard.authorization;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.logging.support.LoggerMessageFormat;
import org.elasticsearch.rest.RestStatus;

public class ForbiddenException extends ElasticsearchException {

	private static final long serialVersionUID = 9118173376408153851L;

	public ForbiddenException(String msg, Object...params) {
		super(LoggerMessageFormat.format(msg, params));
	}

	@Override
	public RestStatus status() {
		return RestStatus.FORBIDDEN;
	}

	

}
