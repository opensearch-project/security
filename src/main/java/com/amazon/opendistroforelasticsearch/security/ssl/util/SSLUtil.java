package com.amazon.opendistroforelasticsearch.security.ssl.util;

import io.netty.buffer.ByteBuf;

import java.nio.ByteOrder;


public class SSLUtil {

    private static final int SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;
    private static final int SSL_CONTENT_TYPE_ALERT = 21;
    private static final int SSL_CONTENT_TYPE_HANDSHAKE = 22;
    private static final int SSL_CONTENT_TYPE_APPLICATION_DATA = 23;
    private static final int SSL_CONTENT_TYPE_EXTENSION_HEARTBEAT = 24;

    private static final int SSL_RECORD_HEADER_LENGTH = 5;

    public boolean isTLS(ByteBuf buffer) {
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

    static private int unsignedShortBE(ByteBuf buffer, int offset) {
        return buffer.order() == ByteOrder.BIG_ENDIAN ?
                buffer.getUnsignedShort(offset) : buffer.getUnsignedShortLE(offset);
    }
}
