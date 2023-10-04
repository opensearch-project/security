/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.http.netty;

import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.HttpContentDecompressor;

import static org.opensearch.security.http.SecurityHttpServerTransport.SHOULD_DECOMPRESS;

public class Netty4ConditionalDecompressor extends HttpContentDecompressor {
    @Override
    protected EmbeddedChannel newContentDecoder(String contentEncoding) throws Exception {
        Boolean shouldDecompress = ctx.channel().attr(SHOULD_DECOMPRESS).get();
        if (shouldDecompress != null) {
            // unset once used
            ctx.channel().attr(SHOULD_DECOMPRESS).set(null);
        }
        if (Boolean.FALSE.equals(shouldDecompress)) {
            return super.newContentDecoder("identity");
        }
        return super.newContentDecoder(contentEncoding);
    }
}
