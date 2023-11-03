/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.cluster;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;

import org.opensearch.test.framework.cluster.OpenSearchClientProvider.UserCredentialsHolder;

import static java.util.Objects.requireNonNull;

/**
* Object which groups some parameters needed for {@link TestRestClient} creation. The class was created to reduce number of parameters
* of methods which are used to create {@link TestRestClient} . The class provides convenient builder-like methods. All fields of a class
* are nullable.
*/
public class TestRestClientConfiguration {

    /**
    * Username
    */
    private String username;
    /**
    * Password
    */
    private String password;
    /**
    * HTTP headers which should be attached to each HTTP request which is sent by {@link TestRestClient}
    */
    private final List<Header> headers = new ArrayList<>();
    /**
    * IP address of client socket of {@link TestRestClient}
    */
    private InetAddress sourceInetAddress;

    /**
    * Set username
    * @param username username
    * @return builder
    */
    public TestRestClientConfiguration username(String username) {
        this.username = username;
        return this;
    }

    /**
    * Set user's password
    * @param password password
    * @return builder
    */
    public TestRestClientConfiguration password(String password) {
        this.password = password;
        return this;
    }

    /**
    * The method sets username and password read form <code>userCredentialsHolder</code>
    * @param userCredentialsHolder source of credentials
    * @return builder
    */
    public TestRestClientConfiguration credentials(UserCredentialsHolder userCredentialsHolder) {
        Objects.requireNonNull(userCredentialsHolder, "User credential holder is required.");
        this.username = userCredentialsHolder.getName();
        this.password = userCredentialsHolder.getPassword();
        return this;
    }

    /**
    * Add HTTP headers which are attached to each HTTP request
    * @param headers headers
    * @return builder
    */
    public TestRestClientConfiguration header(final String headerName, final String headerValue) {
        this.headers.add(
            new BasicHeader(
                Objects.requireNonNull(headerName, "Header names are required"),
                Objects.requireNonNull(headerValue, "Header values are required")
            )
        );
        return this;
    }

    /**
    * Add HTTP headers which are attached to each HTTP request
    * @param headers headers
    * @return builder
    */
    public TestRestClientConfiguration headers(Header... headers) {
        this.headers.addAll(Arrays.asList(Objects.requireNonNull(headers, "Headers are required")));
        return this;
    }

    /**
    * Add HTTP headers which are attached to each HTTP request
    * @param headers list of headers
    * @return builder
    */
    public TestRestClientConfiguration headers(List<Header> headers) {
        this.headers.addAll(Objects.requireNonNull(headers, "Cannot add null headers"));
        return this;
    }

    /**
    * Set IP address of client socket used by {@link TestRestClient}
    * @param sourceInetAddress IP address
    * @return builder
    */
    public TestRestClientConfiguration sourceInetAddress(InetAddress sourceInetAddress) {
        this.sourceInetAddress = sourceInetAddress;
        return this;
    }

    public TestRestClientConfiguration sourceInetAddress(String sourceInetAddress) {
        try {
            this.sourceInetAddress = InetAddress.getByName(sourceInetAddress);
            return this;
        } catch (UnknownHostException e) {
            throw new RuntimeException("Cannot get IP address for string " + sourceInetAddress, e);
        }
    }

    public static TestRestClientConfiguration userWithSourceIp(UserCredentialsHolder credentials, String sourceIpAddress) {
        return new TestRestClientConfiguration().credentials(credentials).sourceInetAddress(sourceIpAddress);
    }

    /**
    * Return complete header list. Basic authentication header is created using fields {@link #username} and {@link #password}
    * @return header list
    */
    List<Header> getHeaders() {
        return Stream.concat(createBasicAuthHeader().stream(), headers.stream()).collect(Collectors.toList());
    }

    private Optional<Header> createBasicAuthHeader() {
        if (containsCredentials()) {
            return Optional.of(getBasicAuthHeader(username, password));
        }
        return Optional.empty();
    }

    private boolean containsCredentials() {
        return StringUtils.isNoneBlank(username) && StringUtils.isNoneBlank(password);
    }

    InetAddress getSourceInetAddress() {
        return sourceInetAddress;
    }

    public static Header getBasicAuthHeader(String user, String password) {
        String value = "Basic "
            + Base64.getEncoder().encodeToString((user + ":" + requireNonNull(password)).getBytes(StandardCharsets.UTF_8));
        return new BasicHeader("Authorization", value);
    }
}
