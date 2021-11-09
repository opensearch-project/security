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

package com.amazon.dlic.auth.http.saml;

public class SamlConfigException extends Exception {

    private static final long serialVersionUID = 6888715101647475455L;

    public SamlConfigException() {
        super();
    }

    public SamlConfigException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public SamlConfigException(String message, Throwable cause) {
        super(message, cause);
    }

    public SamlConfigException(String message) {
        super(message);
    }

    public SamlConfigException(Throwable cause) {
        super(cause);
    }

}
