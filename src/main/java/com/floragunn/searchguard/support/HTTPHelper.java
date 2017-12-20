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

package com.floragunn.searchguard.support;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.apache.logging.log4j.Logger;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.user.AuthCredentials;

public class HTTPHelper {

    public static AuthCredentials extractCredentials(String authorizationHeader, Logger log) {

        if (authorizationHeader != null) {
            if (!authorizationHeader.trim().toLowerCase().startsWith("basic ")) {
                log.warn("No 'Basic Authorization' header, send 401 and 'WWW-Authenticate Basic'");
                return null;
            } else {

                final String decodedBasicHeader = new String(DatatypeConverter.parseBase64Binary(authorizationHeader.split(" ")[1]),
                        StandardCharsets.UTF_8);

                //username:password
                //special case
                //username must not contain a :, but password is allowed to do so
                //   username:pass:word
                //blank password
                //   username:
                
                final int firstColonIndex = decodedBasicHeader.indexOf(':');

                String username = null;
                String password = null;

                if (firstColonIndex > 0) {
                    username = decodedBasicHeader.substring(0, firstColonIndex);
                    
                    if(decodedBasicHeader.length() - 1 != firstColonIndex) {
                        password = decodedBasicHeader.substring(firstColonIndex + 1);
                    } else {
                        //blank password
                        password="";
                    }
                }

                if (username == null || password == null) {
                    log.warn("Invalid 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
                    return null;
                } else {
                    return new AuthCredentials(username, password.getBytes(StandardCharsets.UTF_8)).markComplete();
                }
            }
        } else {
            log.trace("No 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
            return null;
        }
    }
    
    public static boolean containsBadHeader(final RestRequest request) {
        
        final Map<String, List<String>> headers;
        
        if (request != null && ( headers = request.getHeaders()) != null) {
            for (final String key: headers.keySet()) {
                if (    key != null 
                        && key.trim().toLowerCase().startsWith(ConfigConstants.SG_CONFIG_PREFIX.toLowerCase())) {
                    return true;
                }
            }
        }
        
        return false;
    }
}
