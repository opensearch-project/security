/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package com.amazon.dlic.auth.http.saml;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Timer;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.HttpStatus;

import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HTTPMetadataResolver extends AbstractReloadingMetadataResolver {
    private final Logger log = LoggerFactory.getLogger(HTTPMetadataResolver.class);
    private HttpClient httpClient;
    private URI metadataURI;
    private String cachedMetadataETag;
    private String cachedMetadataLastModified;

    public HTTPMetadataResolver(final HttpClient client, final String metadataURL) throws ResolverException {
        this(null, client, metadataURL);
    }

    public HTTPMetadataResolver(final Timer backgroundTaskTimer, final HttpClient client, final String metadataURL)
        throws ResolverException {
        super(backgroundTaskTimer);

        if (client == null) {
            throw new ResolverException("HTTP client may not be null");
        }
        httpClient = client;

        try {
            metadataURI = new URI(metadataURL);
        } catch (final URISyntaxException e) {
            throw new ResolverException("Illegal URL syntax", e);
        }
    }

    public String getMetadataURI() {
        return metadataURI.toASCIIString();
    }

    @Override
    protected void doDestroy() {
        if (httpClient instanceof AutoCloseable) {
            try {
                ((AutoCloseable) httpClient).close();
            } catch (final Exception e) {
                log.error("Error closing HTTP client", e);
            }
        }
        httpClient = null;
        metadataURI = null;
        cachedMetadataETag = null;
        cachedMetadataLastModified = null;

        super.doDestroy();
    }

    @Override
    protected String getMetadataIdentifier() {
        return metadataURI.toString();
    }

    @Override
    protected byte[] fetchMetadata() throws ResolverException {
        final HttpGet httpGet = buildHttpGet();
        final HttpClientContext context = HttpClientContext.create();

        try {
            log.debug("{} Attempting to fetch metadata document from '{}'", getLogPrefix(), metadataURI);
            return httpClient.execute(httpGet, context, response -> {
                final int httpStatusCode = response.getCode();
                if (httpStatusCode == HttpStatus.SC_NOT_MODIFIED) {
                    log.debug("{} Metadata document from '{}' has not changed since last retrieval", getLogPrefix(), getMetadataURI());
                    return null;
                }
                if (httpStatusCode != HttpStatus.SC_OK) {
                    final String errMsg = "Non-ok status code " + httpStatusCode + " returned from remote metadata source " + metadataURI;
                    log.error("{} " + errMsg, getLogPrefix());
                    throw new HttpException(errMsg);
                }

                processConditionalRetrievalHeaders(response);
                try {
                    return getMetadataBytesFromResponse(response);
                } catch (ResolverException e) {
                    final String errMsg = "Error retrieving metadata from " + metadataURI;
                    throw new HttpException(errMsg, e);
                }
            });
        } catch (final IOException e) {
            final String errMsg = "Error retrieving metadata from " + metadataURI;
            log.error("{} {}: {}", getLogPrefix(), errMsg, e.getMessage());
            throw new ResolverException(errMsg, e);
        }
    }

    protected HttpGet buildHttpGet() {
        final HttpGet getMethod = new HttpGet(getMetadataURI());

        if (cachedMetadataETag != null) {
            getMethod.setHeader(HttpHeaders.IF_NONE_MATCH, cachedMetadataETag);
        }
        if (cachedMetadataLastModified != null) {
            getMethod.setHeader(HttpHeaders.IF_MODIFIED_SINCE, cachedMetadataLastModified);
        }

        return getMethod;
    }

    protected void processConditionalRetrievalHeaders(final ClassicHttpResponse response) {
        Header httpHeader = response.getFirstHeader(HttpHeaders.ETAG);
        if (httpHeader != null) {
            cachedMetadataETag = httpHeader.getValue();
        }

        httpHeader = response.getFirstHeader(HttpHeaders.LAST_MODIFIED);
        if (httpHeader != null) {
            cachedMetadataLastModified = httpHeader.getValue();
        }
    }

    protected byte[] getMetadataBytesFromResponse(final ClassicHttpResponse response) throws ResolverException {
        log.debug("{} Attempting to extract metadata from response to request for metadata from '{}'", getLogPrefix(), getMetadataURI());
        try {
            final InputStream ins = response.getEntity().getContent();
            return inputstreamToByteArray(ins);
        } catch (final IOException e) {
            log.error("{} Unable to read response: {}", getLogPrefix(), e.getMessage());
            throw new ResolverException("Unable to read response", e);
        } finally {
            // Make sure entity has been completely consumed.
            EntityUtils.consumeQuietly(response.getEntity());
        }
    }
}
