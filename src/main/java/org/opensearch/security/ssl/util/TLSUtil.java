/*
 * Copyright OpenSearch Contributors
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
package org.opensearch.security.ssl.util;

import io.netty.buffer.ByteBuf;

import java.nio.ByteOrder;


public class TLSUtil {

    private static final int SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;
    private static final int SSL_CONTENT_TYPE_ALERT = 21;
    private static final int SSL_CONTENT_TYPE_HANDSHAKE = 22;
    private static final int SSL_CONTENT_TYPE_APPLICATION_DATA = 23;
    private static final int SSL_CONTENT_TYPE_EXTENSION_HEARTBEAT = 24;
    private static final int SSL_RECORD_HEADER_LENGTH = 5;

    private TLSUtil() {

    }

    public static boolean isTLS(ByteBuf buffer) {
        int packetLength = 0;
        int offset = buffer.readerIndex();

        // SSLv3 or TLS - Check ContentType
        boolean tls;
        switch (buffer.getUnsignedByte(offset)) {
            case SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
            case SSL_CONTENT_TYPE_ALERT:
            case SSL_CONTENT_TYPE_HANDSHAKE:
            case SSL_CONTENT_TYPE_APPLICATION_DATA:
            case SSL_CONTENT_TYPE_EXTENSION_HEARTBEAT:
                tls = true;
                break;
            default:
                // SSLv2 or bad data
                tls = false;
        }

        if (tls) {
            // SSLv3 or TLS - Check ProtocolVersion
            int majorVersion = buffer.getUnsignedByte(offset + 1);
            if (majorVersion == 3) {
                // SSLv3 or TLS
                packetLength = unsignedShortBE(buffer, offset + 3) + SSL_RECORD_HEADER_LENGTH;
                if (packetLength <= SSL_RECORD_HEADER_LENGTH) {
                    // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
                    tls = false;
                }
            } else {
                // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
                tls = false;
            }
        }

        return tls;
    }

    private static int unsignedShortBE(ByteBuf buffer, int offset) {
        return buffer.order() == ByteOrder.BIG_ENDIAN ?
                buffer.getUnsignedShort(offset) : buffer.getUnsignedShortLE(offset);
    }
}
