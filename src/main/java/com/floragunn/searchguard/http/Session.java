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

package com.floragunn.searchguard.http;

import java.io.Serializable;
import java.util.Date;

import com.floragunn.searchguard.authentication.User;

public class Session implements Serializable {

    private static final long serialVersionUID = 8419029942614096336L;
    private final Date created;
    private final String id;
    private final User authenticatedUser;

    Session(final String id, final User authenticatedUser) {
        super();
        if (id == null || authenticatedUser == null) {
            throw new IllegalArgumentException();
        }
        this.created = new Date();
        this.id = id;
        this.authenticatedUser = authenticatedUser;
    }

    public User getAuthenticatedUser() {
        return authenticatedUser;
    }

    public Date getCreated() {
        return created;
    }

    public String getId() {
        return id;
    }

    @Override
    public String toString() {
        return "Session [created=" + created + ", id=" + id + ", authenticatedUser=" + authenticatedUser + "]";
    }

}
