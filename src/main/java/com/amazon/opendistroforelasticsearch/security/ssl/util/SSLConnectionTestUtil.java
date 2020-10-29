/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.ssl.util;

import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class to test if the server supports SSL connections.
 * SSL Check will be done by sending an ES Ping to see if server is replying to pings.
 * Following that a custom client hello message will be sent to the server, if the server
 * side has OpenDistroPortUnificationHandler it will reply with server hello message.
 */
public class SSLConnectionTestUtil {

    private static final Logger logger = LogManager.getLogger(SSLConnectionTestUtil.class);
    public static final byte[] ES_PING_MSG = new byte[]{(byte) 'E', (byte) 'S', (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    public static final String DUAL_MODE_CLIENT_HELLO_MSG = "DUALCM";
    public static final String DUAL_MODE_SERVER_HELLO_MSG = "DUALSM";
    private static final int SOCKET_TIMEOUT_MILLIS = 10 * 1000;
    private boolean esPingReplyReceived;
    private boolean dualSSLProbeReplyReceived;
    private final String host;
    private final int port;
    private Socket overriddenSocket = null;
    private OutputStreamWriter testOutputStreamWriter = null;
    private InputStreamReader testInputStreamReader = null;

    public SSLConnectionTestUtil(final String host, final int port) {
        this.host = host;
        this.port = port;
        esPingReplyReceived = false;
        dualSSLProbeReplyReceived = false;
    }

    @VisibleForTesting
    protected SSLConnectionTestUtil(final String host, final int port, final Socket overriddenSocket, final OutputStreamWriter testOutputStreamWriter,
        final InputStreamReader testInputStreamReader) {
        this.overriddenSocket = overriddenSocket;
        this.testOutputStreamWriter = testOutputStreamWriter;
        this.testInputStreamReader = testInputStreamReader;

        this.host = host;
        this.port = port;
        esPingReplyReceived = false;
        dualSSLProbeReplyReceived = false;
    }

    /**
     * Test connection to server by performing the below steps:
     * - Send Client Hello to check if the server replies with Server Hello which indicates that Server understands SSL
     * - Send ES Ping to check if the server replies to the ES Ping message
     *
     * @return SSLConnectionTestResult i.e. ES_PING_FAILED or SSL_NOT_AVAILABLE or SSL_AVAILABLE
     */
    public SSLConnectionTestResult testConnection() {
        if (sendDualSSLClientHello()) {
            return SSLConnectionTestResult.SSL_AVAILABLE;
        }

        if (sendESPing()) {
            return SSLConnectionTestResult.SSL_NOT_AVAILABLE;
        }

        return SSLConnectionTestResult.ES_PING_FAILED;
    }

    private boolean sendDualSSLClientHello() {
        boolean dualSslSupported = false;
        Socket socket = null;
        try {
            OutputStreamWriter outputStreamWriter;
            InputStreamReader inputStreamReader;
            if(overriddenSocket != null) {
                socket = overriddenSocket;
                outputStreamWriter = testOutputStreamWriter;
                inputStreamReader = testInputStreamReader;
            } else {
                socket = new Socket(host, port);
                outputStreamWriter = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8);
                inputStreamReader = new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8);
            }

            socket.setSoTimeout(SOCKET_TIMEOUT_MILLIS);
            outputStreamWriter.write(DUAL_MODE_CLIENT_HELLO_MSG);
            outputStreamWriter.flush();
            logger.debug("Sent DualSSL Client Hello msg to {}", host);

            StringBuilder sb = new StringBuilder();
            int currentChar;
            while ((currentChar = inputStreamReader.read()) != -1) {
                sb.append((char) currentChar);
            }

            if (sb.toString().equals(DUAL_MODE_SERVER_HELLO_MSG)) {
                logger.debug("Received DualSSL Server Hello msg from {}", host);
                dualSslSupported = true;
            }
        } catch (IOException e) {
            logger.debug("DualSSL client check failed for {}, exception {}", host, e.getMessage());
        } finally {
            logger.debug("Closing DualSSL check client socket for {}", host);
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    logger.error("Exception occurred while closing DualSSL check client socket for {}. Exception: {}", host, e.getMessage());
                }
            }
        }
        logger.debug("dualSslClient check with server {}, server supports ssl = {}", host, dualSslSupported);
        return dualSslSupported;
    }

    private boolean sendESPing() {
        boolean pingSucceeded = false;
        Socket socket = null;
        try {
            if(overriddenSocket != null) {
                socket = overriddenSocket;
            } else {
                socket = new Socket(host, port);
            }

            socket.setSoTimeout(SOCKET_TIMEOUT_MILLIS);
            OutputStream outputStream = socket.getOutputStream();
            InputStream inputStream = socket.getInputStream();

            logger.debug("Sending ES Ping to {}", host);
            outputStream.write(ES_PING_MSG);
            outputStream.flush();

            int currentByte;
            int byteBufIndex = 0;
            byte[] response = new byte[6];
            while ((byteBufIndex < 6) && ((currentByte = inputStream.read()) != -1)) {
                response[byteBufIndex] = (byte) currentByte;
                byteBufIndex++;
            }
            if (byteBufIndex == 6) {
                logger.debug("Received reply for ES Ping. from {}", host);
                pingSucceeded = true;
                for(int i = 0; i < 6; i++) {
                    if (response[i] != ES_PING_MSG[i]) {
                        // Unexpected byte in response
                        logger.error("Received unexpected byte in ES Ping reply from {}", host);
                        pingSucceeded = false;
                        break;
                    }
                }
            }
        } catch (IOException ex) {
            logger.error("ES Ping failed for {}, exception: {}", host, ex.getMessage());
        } finally {
            logger.debug("Closing ES Ping client socket for connection to {}", host);
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    logger.error("Exception occurred while closing socket for {}. Exception: {}", host, e.getMessage());
                }
            }
        }

        logger.debug("ES Ping check to server {} result = {}", host, pingSucceeded);
        return pingSucceeded;
    }
}
