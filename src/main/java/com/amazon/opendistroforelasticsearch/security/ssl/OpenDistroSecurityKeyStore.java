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

package com.amazon.opendistroforelasticsearch.security.ssl;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import java.security.cert.X509Certificate;

public interface OpenDistroSecurityKeyStore {

    public SSLEngine createHTTPSSLEngine() throws SSLException;

    public SSLEngine createServerTransportSSLEngine() throws SSLException;

    public SSLEngine createClientTransportSSLEngine(String peerHost, int peerPort) throws SSLException;

    public String getHTTPProviderName();
    public String getTransportServerProviderName();
    public String getTransportClientProviderName();

    public void initHttpSSLConfig();
    public void initTransportSSLConfig();
    public X509Certificate[] getTransportCerts();
    public X509Certificate[] getHttpCerts();
}
