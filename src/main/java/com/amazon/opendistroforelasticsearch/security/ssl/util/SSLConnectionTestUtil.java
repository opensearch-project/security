package com.amazon.opendistroforelasticsearch.security.ssl.util;

import com.amazon.opendistroforelasticsearch.security.ssl.transport.OpenDistroSSLDualModeConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.cluster.node.DiscoveryNode;

/**
 * Utility class to test if the server supports SSL connections.
 * SSL Check will be done by sending an ES Ping to see if server is replying to pings.
 * Following that a custom client hello message will be sent to the server, if the server
 * side has OpenDistroPortUnificationHandler it will reply with server hello message.
 */
public class SSLConnectionTestUtil {

    private static final Logger logger = LogManager.getLogger(SSLConnectionTestUtil.class);
    public static final byte[] ES_PING_MSG = new byte[]{(byte) 'E', (byte) 'S', (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    private boolean esPingReplyReceived;
    private boolean dualSSLProbeReplyReceived;
    private final DiscoveryNode discoveryNode;

    public SSLConnectionTestUtil(final DiscoveryNode discoveryNode) {
        this.discoveryNode = discoveryNode;
        esPingReplyReceived = false;
        dualSSLProbeReplyReceived = false;
    }

    /**
     * Test connection to server by performing the below steps:
     * - Send ES Ping to check if the server replies to the ES Ping message
     * - Send Client Hello to check if the server replies with Server Hello which indicates that Server understands SSL
     *
     * @return SSLConnectionTestResult i.e. ES_PING_FAILED or SSL_NOT_AVAILABLE or SSL_AVAILABLE
     */
    public SSLConnectionTestResult testConnection() {
        if (!sendESPing()) {
            return SSLConnectionTestResult.ES_PING_FAILED;
        }

        if (!sendDualSSLClientHello()) {
            return SSLConnectionTestResult.SSL_NOT_AVAILABLE;
        }

        return SSLConnectionTestResult.SSL_AVAILABLE;
    }

    private boolean sendDualSSLClientHello() {
        boolean dualSslSupported = false;
        Socket socket = null;
        try {
            socket = new Socket(discoveryNode.getAddress().getAddress(), discoveryNode.getAddress().getPort());

            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8);
            InputStreamReader inputStreamReader = new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8);
            outputStreamWriter.write("DUALCM");
            outputStreamWriter.flush();
            logger.debug("Sent DualSSL Client Hello msg to {}", discoveryNode.getHostName());

            StringBuilder sb = new StringBuilder();
            int currentChar;
            while ((currentChar = inputStreamReader.read()) != -1) {
                sb.append((char) currentChar);
            }

            if (sb.toString().equals("DUALSM")) {
                logger.debug("Received DualSSL Server Hello msg from {}", discoveryNode.getHostName());
                dualSslSupported = true;
            }
        } catch (IOException e) {
            logger.debug("DualSSL client check failed for {}, exception {}", discoveryNode.getHostName(), e.getMessage());
        } finally {
            logger.debug("Closing DualSSL check client socket for {}", discoveryNode.getHostName());
            if (socket != null && socket.isConnected()) {
                try {
                    socket.close();
                } catch (IOException e) {
                    logger.error("Exception occurred while closing DualSSL check client socket for {}. Exception: {}", discoveryNode.getHostName(), e.getMessage());
                }
            }
        }
        logger.debug("dualSslClient check with server {}, server supports ssl = {}", discoveryNode.getHostName(), dualSslSupported);
        return dualSslSupported;
    }

    private boolean sendESPing() {
        boolean pingSucceeded = false;
        Socket socket = null;
        try {
            socket = new Socket(discoveryNode.getAddress().getAddress(), discoveryNode.getAddress().getPort());
            OutputStream outputStream = socket.getOutputStream();
            InputStream inputStream = socket.getInputStream();

            logger.debug("Sending ES Ping to {}", discoveryNode.getHostName());
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
                logger.debug("Received reply for ES Ping. from {}", discoveryNode.getHostName());
                pingSucceeded = true;
                for(int i = 0; i < 6; i++) {
                    if (response[i] != ES_PING_MSG[i]) {
                        // Unexpected byte in response
                        logger.error("Received unexpected byte in ES Ping reply from {}", discoveryNode.getHostName());
                        pingSucceeded = false;
                        break;
                    }
                }
            }
        } catch (IOException ex) {
            logger.error("ES Ping failed for {}, exception: {}", discoveryNode.getHostName(), ex.getMessage());
        } finally {
            logger.debug("Closing ES Ping client socket for connection to {}", discoveryNode.getHostName());
            if (socket != null && socket.isConnected()) {
                try {
                    socket.close();
                } catch (IOException e) {
                    logger.error("Exception occurred while closing socket for {}. Exception: {}", discoveryNode.getHostName(), e.getMessage());
                }
            }
        }

        logger.debug("ES Ping check to server {} result = {}", discoveryNode.getHostName(), pingSucceeded);
        return pingSucceeded;
    }
}
