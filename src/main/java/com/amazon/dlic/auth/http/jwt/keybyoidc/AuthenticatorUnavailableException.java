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

package com.amazon.dlic.auth.http.jwt.keybyoidc;

public class AuthenticatorUnavailableException extends RuntimeException {
	private static final long serialVersionUID = -7007025852090301416L;

	public AuthenticatorUnavailableException() {
		super();
	}

	public AuthenticatorUnavailableException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public AuthenticatorUnavailableException(String message, Throwable cause) {
		super(message, cause);
	}

	public AuthenticatorUnavailableException(String message) {
		super(message);
	}

	public AuthenticatorUnavailableException(Throwable cause) {
		super(cause);
	}

}
