package com.amazon.opendistroforelasticsearch.security.ssl.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class OpenDistroSSLMode {
    private static final Logger logger = LogManager.getLogger(OpenDistroSSLMode.class);
    public static boolean isDualSSLMode() {
        boolean noSSLMode = System.getenv().getOrDefault("DUAL_SSL_MODE", "FALSE").equals("TRUE");
        logger.info("DUAL_SSL_MODE: "+noSSLMode);
        return noSSLMode;
    }
}
