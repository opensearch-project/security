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

package com.floragunn.searchguard.http.netty;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.netty.handler.codec.http.Cookie;
import org.elasticsearch.common.netty.handler.codec.http.CookieEncoder;
import org.elasticsearch.common.netty.handler.codec.http.DefaultCookie;
import org.elasticsearch.http.netty.NettyHttpRequest;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestResponse;

import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.http.Session;
import com.floragunn.searchguard.http.SessionStore;
import com.floragunn.searchguard.http.netty.MutualSSLHandler.DefaultHttpsRequest;
import com.floragunn.searchguard.util.SecurityUtil;

public class SessionAwareNettyHttpChannel extends RestChannel {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final SessionStore sessionStore;
    private final RestChannel channel;

    public SessionAwareNettyHttpChannel(final RestChannel channel, final SessionStore sessionStore, final boolean detailedErrorsEnabled) {
        super(channel.request(), detailedErrorsEnabled);
        this.channel = channel;
        this.sessionStore = sessionStore;
    }

    @Override
    public void sendResponse(final RestResponse response) {

        final User user = this.request.getFromContext("searchguard_authenticated_user");
        final Session _session = sessionStore.getSession(SecurityUtil.getSearchGuardSessionIdFromCookie(request));

        if (user != null) {
            if (_session == null) {
                final Session session = sessionStore.createSession(user);
                log.trace("Create session and set cookie for {}", user.getName());
                final CookieEncoder encoder = new CookieEncoder(true);
                final Cookie cookie = new DefaultCookie("es_searchguard_session", session.getId());

                //TODO FUTURE check cookie domain/path
                //cookie.setDomain(arg0);
                //cookie.setPath(arg0);

                cookie.setDiscard(true);
                cookie.setSecure(((NettyHttpRequest) request).request() instanceof DefaultHttpsRequest);
                cookie.setMaxAge(60 * 60); //1h
                cookie.setHttpOnly(true);
                encoder.addCookie(cookie);
                response.addHeader("Set-Cookie", encoder.encode());
            } else {

                //Set-Cookie: token=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT
                log.trace("There is already a session");
                //TODO FUTURE check cookie seesion validity, expire, ...

            }

        }

        channel.sendResponse(response);
    }

}
