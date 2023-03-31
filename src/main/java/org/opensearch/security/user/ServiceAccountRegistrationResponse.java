/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.user;


public class ServiceAccountRegistrationResponse {

    //TODO: May not need this class; could move into ExtensionHelper
    private final String extensionUniqueId;

    private boolean registrationComplete;

    public ServiceAccountRegistrationResponse(String extensionUniqueId) {
        this.extensionUniqueId = extensionUniqueId;
        this.registrationComplete = extensionIsRegistered();
    }

    public boolean extensionIsRegistered(){ // Todo: This should make sure that the registration is propagated to all nodes, not sure how to do that

        if (registrationComplete) {
            return true;
        }
        if (UserService.accountExists(this.extensionUniqueId)) {
            this.registrationComplete = true;
            return true;
        }
        return false;
    }

    public String getExtensionUniqueId() { return extensionUniqueId; }

    public boolean getRegistrationComplete() { return registrationComplete; }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (this.getClass() != obj.getClass()) {
            return false;
        }
        ServiceAccountRegistrationResponse otherExReg = (ServiceAccountRegistrationResponse) (obj);
        if (!this.extensionUniqueId.equals(otherExReg.extensionUniqueId)) {
            return false;
            }
        return true;
    }
}
