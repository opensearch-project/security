/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.http.netty;

import org.opensearch.security.filter.NettyAttribute;

import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.HttpContentDecompressor;

public class Netty4ConditionalDecompressor extends HttpContentDecompressor {

    @Override
    protected EmbeddedChannel newContentDecoder(String contentEncoding) throws Exception {
        final boolean hasAnEarlyReponse = NettyAttribute.peekFrom(ctx, Netty4HttpRequestHeaderVerifier.EARLY_RESPONSE).isPresent();
        final boolean shouldDecompress = NettyAttribute.popFrom(ctx, Netty4HttpRequestHeaderVerifier.SHOULD_DECOMPRESS).orElse(false);
        if (hasAnEarlyReponse || !shouldDecompress) {
            // If there was an error prompting an early response,... don't decompress
            // If there is no explicit decompress flag,... don't decompress
            // If there is a decompress flag and it is false,... don't decompress
            return super.newContentDecoder("identity");
        }

        // Decompresses the content based on its encoding
        return super.newContentDecoder(contentEncoding);
    }
}
