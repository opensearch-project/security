/*
 * Portions Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
    public void testConnectionEsPingFailed() throws Exception {
        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);

        Mockito.when(socket.getOutputStream()).thenReturn(outputStream);
        Mockito.when(socket.getInputStream()).thenReturn(inputStream);
        Mockito.doNothing().when(outputStream).write(Mockito.any(byte[].class));
        Mockito.when(inputStream.read())
            .thenReturn(-1);
        Mockito.when(socket.isConnected()).thenReturn(true);
        Mockito.doNothing().when(socket).close();


        SSLConnectionTestResult result = connectionTestUtil.testConnection();
        ArgumentCaptor<byte[]> argumentCaptor = ArgumentCaptor.forClass(byte[].class);
        Mockito.verify(outputStream,
            Mockito.times(1))
            .write(argumentCaptor.capture());
        byte[] bytesWritten = argumentCaptor.getValue();
        byte[] expectedBytes = new byte[]{'E','S',(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
        for(int i = 0; i < bytesWritten.length; i++) {
            Assert.assertEquals("Unexpected bytes written to socket", expectedBytes[i], bytesWritten[i]);
        }
        Mockito.verify(socket, Mockito.times(1)).close();

        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.ES_PING_FAILED, result);
    }

    @Test
    public void testConnectionEsPingFailedInvalidReply() throws Exception {
        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);

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
        Mockito.when(socket.isConnected()).thenReturn(true);
        Mockito.doNothing().when(socket).close();


        SSLConnectionTestResult result = connectionTestUtil.testConnection();
        ArgumentCaptor<byte[]> argumentCaptor = ArgumentCaptor.forClass(byte[].class);
        Mockito.verify(outputStream,
            Mockito.times(1))
            .write(argumentCaptor.capture());
        byte[] bytesWritten = argumentCaptor.getValue();
        byte[] expectedBytes = new byte[]{'E','S',(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
        for(int i = 0; i < bytesWritten.length; i++) {
            Assert.assertEquals("Unexpected bytes written to socket", expectedBytes[i], bytesWritten[i]);
        }
        Mockito.verify(socket, Mockito.times(1)).close();

        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.ES_PING_FAILED, result);
    }

    @Test
    public void testConnectionEsPingFailedIOException() throws Exception {
        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);

        Mockito.when(socket.getOutputStream()).thenReturn(outputStream);
        Mockito.when(socket.getInputStream()).thenReturn(inputStream);
        Mockito.doThrow(new IOException("Error while writing bytes to output stream")).when(outputStream).write(Mockito.any(byte[].class));
        Mockito.when(socket.isConnected()).thenReturn(true);
        Mockito.doNothing().when(socket).close();


        SSLConnectionTestResult result = connectionTestUtil.testConnection();
        ArgumentCaptor<byte[]> argumentCaptor = ArgumentCaptor.forClass(byte[].class);
        Mockito.verify(outputStream,
            Mockito.times(1))
            .write(argumentCaptor.capture());
        byte[] bytesWritten = argumentCaptor.getValue();
        byte[] expectedBytes = new byte[]{'E','S',(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
        for(int i = 0; i < bytesWritten.length; i++) {
            Assert.assertEquals("Unexpected bytes written to socket", expectedBytes[i], bytesWritten[i]);
        }
        Mockito.verifyZeroInteractions(inputStream);
        Mockito.verify(socket, Mockito.times(1)).close();
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.ES_PING_FAILED, result);
    }

    @Test
    public void testConnectionEsPingFailedIOExceptionSocketClosed() throws Exception {
        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);

        Mockito.when(socket.getOutputStream()).thenReturn(outputStream);
        Mockito.when(socket.getInputStream()).thenReturn(inputStream);
        Mockito.doThrow(new IOException("Socket closed")).when(outputStream).write(Mockito.any(byte[].class));
        Mockito.when(socket.isConnected()).thenReturn(false);


        SSLConnectionTestResult result = connectionTestUtil.testConnection();
        ArgumentCaptor<byte[]> argumentCaptor = ArgumentCaptor.forClass(byte[].class);
        Mockito.verify(outputStream,
            Mockito.times(1))
            .write(argumentCaptor.capture());
        byte[] bytesWritten = argumentCaptor.getValue();
        byte[] expectedBytes = new byte[]{'E','S',(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
        for(int i = 0; i < bytesWritten.length; i++) {
            Assert.assertEquals("Unexpected bytes written to socket", expectedBytes[i], bytesWritten[i]);
        }
        Mockito.verifyZeroInteractions(inputStream);
        Mockito.verify(socket, Mockito.times(0)).close();
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.ES_PING_FAILED, result);
    }

    @Test
    public void testConnectionSSLNotAvailable() throws Exception {
        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);

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

        Mockito.doNothing().when(outputStreamWriter).write(Mockito.anyString());
        Mockito.when(inputStreamReader.read())
            .thenReturn(-1);
        Mockito.when(socket.isConnected()).thenReturn(true);
        Mockito.doNothing().when(socket).close();


        SSLConnectionTestResult result = connectionTestUtil.testConnection();

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(outputStreamWriter,
            Mockito.times(1))
            .write(argumentCaptor.capture());
        String msgWritten = argumentCaptor.getValue();
        String expectedMsg = "DUALCM";
        Mockito.verify(socket, Mockito.times(2)).close();

        Assert.assertEquals("Unexpected message written to socket", expectedMsg, msgWritten);
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.SSL_NOT_AVAILABLE, result);
    }

    @Test
    public void testConnectionSSLNotAvailableIOException() throws Exception {
        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);

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

        Mockito.doNothing().when(outputStreamWriter).write(Mockito.anyString());
        Mockito.doThrow(new IOException("Error while writing bytes to output stream")).when(outputStreamWriter).write(Mockito.anyString());
        Mockito.when(socket.isConnected())
            .thenReturn(true);
        Mockito.doNothing().when(socket).close();

        SSLConnectionTestResult result = connectionTestUtil.testConnection();

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(outputStreamWriter,
            Mockito.times(1))
            .write(argumentCaptor.capture());
        String msgWritten = argumentCaptor.getValue();
        String expectedMsg = "DUALCM";
        Mockito.verifyZeroInteractions(inputStreamReader);
        Mockito.verify(socket, Mockito.times(2)).close();

        Assert.assertEquals("Unexpected message written to socket", expectedMsg, msgWritten);
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.SSL_NOT_AVAILABLE, result);
    }

    @Test
    public void testConnectionSSLNotAvailableIOExceptionSocketClosed() throws Exception {
        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);

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

        Mockito.doNothing().when(outputStreamWriter).write(Mockito.anyString());
        Mockito.doThrow(new IOException("Socket closed")).when(outputStreamWriter).write(Mockito.anyString());
        Mockito.when(socket.isConnected())
            .thenReturn(true)
            .thenReturn(false);
        Mockito.doNothing().when(socket).close();

        SSLConnectionTestResult result = connectionTestUtil.testConnection();

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(outputStreamWriter,
            Mockito.times(1))
            .write(argumentCaptor.capture());
        String msgWritten = argumentCaptor.getValue();
        String expectedMsg = "DUALCM";
        Mockito.verifyZeroInteractions(inputStreamReader);
        Mockito.verify(socket, Mockito.times(1)).close();

        Assert.assertEquals("Unexpected message written to socket", expectedMsg, msgWritten);
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.SSL_NOT_AVAILABLE, result);
    }

    @Test
    public void testConnectionSSLAvailable() throws Exception {
        SSLConnectionTestUtil connectionTestUtil = new SSLConnectionTestUtil("127.0.0.1", 443, socket, outputStreamWriter, inputStreamReader);

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

        Mockito.doNothing().when(outputStreamWriter).write(Mockito.anyString());
        Mockito.when(inputStreamReader.read())
            .thenReturn((int)'D')
            .thenReturn((int)'U')
            .thenReturn((int)'A')
            .thenReturn((int)'L')
            .thenReturn((int)'S')
            .thenReturn((int)'M')
            .thenReturn(-1);
        Mockito.when(socket.isConnected()).thenReturn(true);
        Mockito.doNothing().when(socket).close();


        SSLConnectionTestResult result = connectionTestUtil.testConnection();

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(outputStreamWriter,
            Mockito.times(1))
            .write(argumentCaptor.capture());
        String msgWritten = argumentCaptor.getValue();
        String expectedMsg = "DUALCM";
        Mockito.verify(socket, Mockito.times(2)).close();

        Assert.assertEquals("Unexpected message written to socket", expectedMsg, msgWritten);
        Assert.assertEquals("Unexpected result for testConnection invocation", SSLConnectionTestResult.SSL_AVAILABLE, result);
    }
}
