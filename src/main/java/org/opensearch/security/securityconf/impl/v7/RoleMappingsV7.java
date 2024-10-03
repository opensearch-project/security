/*
 * Copyright 2015-2017 floragunn GmbH
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

package org.opensearch.security.securityconf.impl.v7;

import java.util.Collections;
import java.util.List;

import org.opensearch.security.securityconf.Hideable;
import org.opensearch.security.securityconf.RoleMappings;

public class RoleMappingsV7 extends RoleMappings implements Hideable {

    private boolean reserved;
    private boolean hidden;
    private List<String> backend_roles = Collections.emptyList();
    private List<String> and_backend_roles = Collections.emptyList();
    private String description;

    public RoleMappingsV7() {
        super();
    }

    public boolean isReserved() {
        return reserved;
    }

    public void setReserved(boolean reserved) {
        this.reserved = reserved;
    }

    public boolean isHidden() {
        return hidden;
    }

    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }

    public List<String> getBackend_roles() {
        return backend_roles;
    }

    public void setBackend_roles(List<String> backend_roles) {
        this.backend_roles = backend_roles;
    }

    public List<String> getAnd_backend_roles() {
        return and_backend_roles;
    }

    public void setAnd_backend_roles(List<String> and_backend_roles) {
        this.and_backend_roles = and_backend_roles;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String toString() {
        return "RoleMappingsV7 [reserved="
            + reserved
            + ", hidden="
            + hidden
            + ", backend_roles="
            + backend_roles
            + ", hosts="
            + getHosts()
            + ", users="
            + getUsers()
            + ", and_backend_roles="
            + and_backend_roles
            + ", description="
            + description
            + "]";
    }

}
