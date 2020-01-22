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

package com.amazon.dlic.auth.ldap.srv;


public class EmbeddedLDAPServer {

    LdapServer s = new LdapServer();

    public int applyLdif(final String... ldifFile) throws Exception {
        return s.start(ldifFile);
    }

    public void start() throws Exception {

    }

    public void stop() throws Exception {
        s.stop();
    }

    public int getLdapPort() {
        return s.getLdapPort();
    }

    public int getLdapsPort() {
        return s.getLdapsPort();
    }
}