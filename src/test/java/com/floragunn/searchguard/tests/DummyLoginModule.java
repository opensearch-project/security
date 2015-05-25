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

package com.floragunn.searchguard.tests;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

public class DummyLoginModule implements LoginModule {

    private Map sharedState;
    public static String username;
    public static char[] password;

    public DummyLoginModule() {
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map<String, ?> sharedState,
            final Map<String, ?> options) {
        this.sharedState = sharedState;
    }

    @Override
    public boolean login() throws LoginException {
        sharedState.put("javax.security.auth.login.name", username);
        sharedState.put("javax.security.auth.login.password", password);
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }

}