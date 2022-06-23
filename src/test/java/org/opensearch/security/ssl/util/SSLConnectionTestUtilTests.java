/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package org.opensearch.security.ssl.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

public class SSLConnectionTestUtilTests {
    private Socket socket;
    private OutputStream outputStream;
    private InputStream inputStream;
    private OutputStreamWriter outputStreamWriter;
    private InputStreamReader inputStreamReader;

    @Before
    public void setup() {
        socket = Mockito.mock(Socket.class);
        outputStream = Mockito.mock(OutputStream.class);
        inputStream = Mockito.mock(InputStream.class);
        outputStreamWriter = Mockito.mock(OutputStreamWriter.class);
        inputStreamReader = Mockito.mock(InputStreamReader.class);
    }

    @Test
    public void testConnectionSSLAvailable() throws Exception {
        Mockito.doNothing().when(outputStreamWriter).write(Mockito.anyString());
        Mockito.when(inputStreamReader.read())
            .thenReturn((int)'D')
            .thenReturn((int)'U')
            .thenReturn((int)'A')
            .thenReturn((int)'L')
            .thenReturn((int)'S')
            .thenReturn((int)'M')
            .thenReturn(-1);
        Mockito.doNothing().when(socket).close();

        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);
        SSLConnectionTestResult result = connectionTestUtil.testConnection();

        verifyClientHelloSend();
        Mockito.verify(socket, Mockito.times(1)).close();
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.SSL_AVAILABLE, result);
    }

    @Test
    public void testConnectionSSLNotAvailable() throws Exception {
        setupMocksForClientHelloFailure();
        setupMocksForOpenSearchPingSuccess();
        Mockito.doNothing().when(socket).close();

        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);
        SSLConnectionTestResult result = connectionTestUtil.testConnection();

        verifyClientHelloSend();
        verifyOpenSearchPingSend();
        Mockito.verify(socket, Mockito.times(2)).close();
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.SSL_NOT_AVAILABLE, result);
    }

    @Test
    public void testConnectionSSLNotAvailableIOException() throws Exception {
        Mockito.doThrow(new IOException("Error while writing bytes to output stream"))
            .when(outputStreamWriter)
            .write(Mockito.anyString());
        setupMocksForOpenSearchPingSuccess();
        Mockito.doNothing().when(socket).close();

        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);
        SSLConnectionTestResult result = connectionTestUtil.testConnection();

        verifyClientHelloSend();
        Mockito.verifyNoInteractions(inputStreamReader);
        verifyOpenSearchPingSend();
        Mockito.verify(socket, Mockito.times(2)).close();
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.SSL_NOT_AVAILABLE, result);
    }

    @Test
    public void testConnectionOpenSearchPingFailed() throws Exception {
        setupMocksForClientHelloFailure();
        Mockito.when(socket.getOutputStream()).thenReturn(outputStream);
        Mockito.when(socket.getInputStream()).thenReturn(inputStream);
        Mockito.doNothing().when(outputStream).write(Mockito.any(byte[].class));
        Mockito.when(inputStream.read())
            .thenReturn(-1);
        Mockito.doNothing().when(socket).close();

        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);
        SSLConnectionTestResult result = connectionTestUtil.testConnection();

        verifyClientHelloSend();
        verifyOpenSearchPingSend();
        Mockito.verify(socket, Mockito.times(2)).close();
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.OPENSEARCH_PING_FAILED, result);
    }

    @Test
    public void testConnectionOpenSearchPingFailedInvalidReply() throws Exception {
        setupMocksForClientHelloFailure();
        Mockito.when(socket.getOutputStream()).thenReturn(outputStream);
        Mockito.when(socket.getInputStream()).thenReturn(inputStream);
        Mockito.doNothing().when(outputStream).write(Mockito.any(byte[].class));
        Mockito.when(inputStream.read())
            .thenReturn((int)'E')
            .thenReturn((int)'E')
            .thenReturn(0xFF)
            .thenReturn(0xFF)
            .thenReturn(0xFF)
            .thenReturn(0xFF);
        Mockito.doNothing().when(socket).close();

        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);
        SSLConnectionTestResult result = connectionTestUtil.testConnection();

        verifyClientHelloSend();
        verifyOpenSearchPingSend();
        Mockito.verify(socket, Mockito.times(2)).close();
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.OPENSEARCH_PING_FAILED, result);
    }

    @Test
    public void testConnectionOpenSearchPingFailedIOException() throws Exception {
        setupMocksForClientHelloFailure();
        Mockito.when(socket.getOutputStream()).thenReturn(outputStream);
        Mockito.when(socket.getInputStream()).thenReturn(inputStream);
        Mockito.doThrow(new IOException("Error while writing bytes to output stream")).when(outputStream).write(Mockito.any(byte[].class));
        Mockito.doNothing().when(socket).close();

        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);
        SSLConnectionTestResult result = connectionTestUtil.testConnection();

        verifyClientHelloSend();
        verifyOpenSearchPingSend();
        Mockito.verifyNoInteractions(inputStream);
        Mockito.verify(socket, Mockito.times(2)).close();
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.OPENSEARCH_PING_FAILED, result);
    }

    private void verifyClientHelloSend() throws IOException {
        ArgumentCaptor<String> clientHelloMsgArgCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(outputStreamWriter,
            Mockito.times(1))
            .write(clientHelloMsgArgCaptor.capture());
        String msgWritten = clientHelloMsgArgCaptor.getValue();
        String expectedMsg = "DUALCM";
        Assert.assertEquals("Unexpected Dual SSL Client Hello message written to socket", expectedMsg, msgWritten);
    }

    private void verifyOpenSearchPingSend() throws IOException {
        ArgumentCaptor<byte[]> argumentCaptor = ArgumentCaptor.forClass(byte[].class);
        Mockito.verify(outputStream,
            Mockito.times(1))
            .write(argumentCaptor.capture());
        byte[] bytesWritten = argumentCaptor.getValue();
        byte[] expectedBytes = new byte[]{'E','S',(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
        for(int i = 0; i < bytesWritten.length; i++) {
            Assert.assertEquals("Unexpected OpenSearch Ping bytes written to socket", expectedBytes[i], bytesWritten[i]);
        }
    }

    private void setupMocksForClientHelloFailure() throws IOException {
        Mockito.doNothing().when(outputStreamWriter).write(Mockito.anyString());
        Mockito.when(inputStreamReader.read())
            .thenReturn(-1);
    }

    private void setupMocksForOpenSearchPingSuccess() throws IOException {
        Mockito.when(socket.getOutputStream()).thenReturn(outputStream);
        Mockito.when(socket.getInputStream()).thenReturn(inputStream);
        Mockito.doNothing().when(outputStream).write(Mockito.any(byte[].class));
        Mockito.when(inputStream.read())
            .thenReturn((int)'E')
            .thenReturn((int)'S')
            .thenReturn(0xFF)
            .thenReturn(0xFF)
            .thenReturn(0xFF)
            .thenReturn(0xFF);
    }
}
