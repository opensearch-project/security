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

package org.opensearch.security.ssl;

import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

public interface SecurityKeyStore {

    SSLEngine createHTTPSSLEngine() throws SSLException;

    SSLEngine createServerTransportSSLEngine() throws SSLException;

    SSLEngine createClientTransportSSLEngine(String peerHost, int peerPort) throws SSLException;

    String getHTTPProviderName();

    String getTransportServerProviderName();

    String getTransportClientProviderName();

    String getSubjectAlternativeNames(X509Certificate cert);

    void initHttpSSLConfig();

    void initTransportSSLConfig();

    X509Certificate[] getTransportCerts();

    X509Certificate[] getHttpCerts();
}
