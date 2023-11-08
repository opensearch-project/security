/*
* Copyright 2002-2020 the original author or authors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      https://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

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

package org.opensearch.test.framework.cluster;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.SortedSet;
import javax.net.ServerSocketFactory;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.opensearch.test.framework.cluster.SocketUtils.PORT_RANGE_MAX;
import static org.opensearch.test.framework.cluster.SocketUtils.PORT_RANGE_MIN;
import static org.junit.Assert.assertThrows;

/**
* Unit tests for {@link SocketUtils}.
*
* @author Sam Brannen
* @author Gary Russell
*/
public class SocketUtilsTests {

    // TCP

    @Test
    public void findAvailableTcpPort() {
        int port = SocketUtils.findAvailableTcpPort();
        assertPortInRange(port, PORT_RANGE_MIN, PORT_RANGE_MAX);
    }

    @Test
    public void findAvailableTcpPortWithMinPortEqualToMaxPort() {
        int minMaxPort = SocketUtils.findAvailableTcpPort();
        int port = SocketUtils.findAvailableTcpPort(minMaxPort, minMaxPort);
        assertThat(port, equalTo(minMaxPort));
    }

    @Test
    public void findAvailableTcpPortWhenPortOnLoopbackInterfaceIsNotAvailable() throws Exception {
        int port = SocketUtils.findAvailableTcpPort();
        try (ServerSocket socket = ServerSocketFactory.getDefault().createServerSocket(port, 1, InetAddress.getByName("localhost"))) {
            assertThat(socket, notNullValue());
            // will only look for the exact port
            IllegalStateException exception = assertThrows(IllegalStateException.class, () -> SocketUtils.findAvailableTcpPort(port, port));
            assertThat(exception.getMessage(), startsWith("Could not find an available TCP port"));
            assertThat(exception.getMessage(), endsWith("after 1 attempts"));
        }
    }

    @Test
    public void findAvailableTcpPortWithMin() {
        int port = SocketUtils.findAvailableTcpPort(50000);
        assertPortInRange(port, 50000, PORT_RANGE_MAX);
    }

    @Test
    public void findAvailableTcpPortInRange() {
        int minPort = 20000;
        int maxPort = minPort + 1000;
        int port = SocketUtils.findAvailableTcpPort(minPort, maxPort);
        assertPortInRange(port, minPort, maxPort);
    }

    @Test
    public void find4AvailableTcpPorts() {
        findAvailableTcpPorts(4);
    }

    @Test
    public void find50AvailableTcpPorts() {
        findAvailableTcpPorts(50);
    }

    @Test
    public void find4AvailableTcpPortsInRange() {
        findAvailableTcpPorts(4, 30000, 35000);
    }

    @Test
    public void find50AvailableTcpPortsInRange() {
        findAvailableTcpPorts(50, 40000, 45000);
    }

    // UDP

    @Test
    public void findAvailableUdpPort() {
        int port = SocketUtils.findAvailableUdpPort();
        assertPortInRange(port, PORT_RANGE_MIN, PORT_RANGE_MAX);
    }

    @Test
    public void findAvailableUdpPortWhenPortOnLoopbackInterfaceIsNotAvailable() throws Exception {
        int port = SocketUtils.findAvailableUdpPort();
        try (DatagramSocket socket = new DatagramSocket(port, InetAddress.getByName("localhost"))) {
            assertThat(socket, notNullValue());
            // will only look for the exact port
            IllegalStateException exception = assertThrows(IllegalStateException.class, () -> SocketUtils.findAvailableUdpPort(port, port));
            assertThat(exception.getMessage(), startsWith("Could not find an available UDP port"));
            assertThat(exception.getMessage(), endsWith("after 1 attempts"));
        }
    }

    @Test
    public void findAvailableUdpPortWithMin() {
        int port = SocketUtils.findAvailableUdpPort(50000);
        assertPortInRange(port, 50000, PORT_RANGE_MAX);
    }

    @Test
    public void findAvailableUdpPortInRange() {
        int minPort = 20000;
        int maxPort = minPort + 1000;
        int port = SocketUtils.findAvailableUdpPort(minPort, maxPort);
        assertPortInRange(port, minPort, maxPort);
    }

    @Test
    public void find4AvailableUdpPorts() {
        findAvailableUdpPorts(4);
    }

    @Test
    public void find50AvailableUdpPorts() {
        findAvailableUdpPorts(50);
    }

    @Test
    public void find4AvailableUdpPortsInRange() {
        findAvailableUdpPorts(4, 30000, 35000);
    }

    @Test
    public void find50AvailableUdpPortsInRange() {
        findAvailableUdpPorts(50, 40000, 45000);
    }

    // Helpers

    private void findAvailableTcpPorts(int numRequested) {
        SortedSet<Integer> ports = SocketUtils.findAvailableTcpPorts(numRequested);
        assertAvailablePorts(ports, numRequested, PORT_RANGE_MIN, PORT_RANGE_MAX);
    }

    private void findAvailableTcpPorts(int numRequested, int minPort, int maxPort) {
        SortedSet<Integer> ports = SocketUtils.findAvailableTcpPorts(numRequested, minPort, maxPort);
        assertAvailablePorts(ports, numRequested, minPort, maxPort);
    }

    private void findAvailableUdpPorts(int numRequested) {
        SortedSet<Integer> ports = SocketUtils.findAvailableUdpPorts(numRequested);
        assertAvailablePorts(ports, numRequested, PORT_RANGE_MIN, PORT_RANGE_MAX);
    }

    private void findAvailableUdpPorts(int numRequested, int minPort, int maxPort) {
        SortedSet<Integer> ports = SocketUtils.findAvailableUdpPorts(numRequested, minPort, maxPort);
        assertAvailablePorts(ports, numRequested, minPort, maxPort);
    }

    private void assertPortInRange(int port, int minPort, int maxPort) {
        assertThat("port [" + port + "] >= " + minPort, port, greaterThanOrEqualTo(minPort));
        assertThat("port [" + port + "] <= " + maxPort, port, lessThanOrEqualTo(maxPort));
    }

    private void assertAvailablePorts(SortedSet<Integer> ports, int numRequested, int minPort, int maxPort) {
        assertThat("number of ports requested", ports.size(), equalTo(numRequested));
        for (int port : ports) {
            assertPortInRange(port, minPort, maxPort);
        }
    }

}
