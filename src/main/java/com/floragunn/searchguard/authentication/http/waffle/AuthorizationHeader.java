/**
Copyright (c) Application Security Inc., 2010-2014 and Contributors.

This project is licensed under the Eclipse Public License.
See https://github.com/dblock/waffle/blob/master/LICENSE

Project maintained by Daniel Doubrovkine & Jeremy Landis.
 */
package com.floragunn.searchguard.authentication.http.waffle;

/**
 * Waffle (https://github.com/dblock/waffle)
 *
 * Copyright (c) 2010 - 2014 Application Security, Inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Application Security, Inc.
 */
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;

import waffle.util.NtlmMessage;
import waffle.util.SPNegoMessage;

import com.floragunn.searchguard.authentication.AuthException;
import com.google.common.io.BaseEncoding;

/**
 * Authorization header.
 * 
 * Adapted for working without servlet api
 * 
 * @author dblock[at]dblock[dot]org
 */
public class AuthorizationHeader {

    private final RestRequest request;

    public AuthorizationHeader(final RestRequest restRequest) {
        this.request = restRequest;
    }

    public String getHeader() {
        return this.request.header("Authorization");
    }

    public boolean isNull() {
        return getHeader() == null || getHeader().length() == 0;
    }

    /**
     * Returns a supported security package string.
     * 
     * @return Negotiate or NTLM.
     * @throws AuthException
     */
    public String getSecurityPackage() throws AuthException {
        final String header = getHeader();

        if (header == null) {
            throw new AuthException("Missing Authorization: header");
        }

        final int space = header.indexOf(' ');
        if (space > 0) {
            return header.substring(0, space);
        }

        throw new AuthException("Invalid Authorization header: " + header);
    }

    @Override
    public String toString() {
        return isNull() ? "<none>" : getHeader();
    }

    public String getToken() throws AuthException {
        return getHeader().substring(getSecurityPackage().length() + 1);
    }

    public byte[] getTokenBytes() throws AuthException {
        try {
            return BaseEncoding.base64().decode(getToken());
        } catch (final IllegalArgumentException e) {
            throw new AuthException("Invalid authorization header.");
        }
    }

    public boolean isNtlmType1Message() throws AuthException {
        if (isNull()) {
            return false;
        }

        final byte[] tokenBytes = getTokenBytes();
        if (!NtlmMessage.isNtlmMessage(tokenBytes)) {
            return false;
        }

        return 1 == NtlmMessage.getMessageType(tokenBytes);
    }

    public boolean isSPNegoMessage() throws AuthException {

        if (isNull()) {
            return false;
        }

        final byte[] tokenBytes = getTokenBytes();
        if (!SPNegoMessage.isSPNegoMessage(tokenBytes)) {
            return false;
        }

        return true;
    }

    /**
     * When using NTLM authentication and the browser is making a POST request, it preemptively sends a Type 2
     * authentication message (without the POSTed data). The server responds with a 401, and the browser sends a Type 3
     * request with the POSTed data. This is to avoid the situation where user's credentials might be potentially
     * invalid, and all this data is being POSTed across the wire.
     * 
     * @return True if request is an NTLM POST or PUT with an Authorization header and no data.
     * @throws AuthException
     */
    public boolean isNtlmType1PostAuthorizationHeader() throws AuthException {
        if (this.request.method() != Method.POST && this.request.method() != Method.PUT) {
            return false;
        }

        if (this.request.content() != null && this.request.content().length() > 0) {
            return false;
        }

        return isNtlmType1Message() || isSPNegoMessage();
    }
}
