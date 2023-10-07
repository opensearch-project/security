package org.opensearch.security.filter;

public class SecurityRestUtils {
    public static String path(final String uri) {
        final int index = uri.indexOf('?');
        if (index >= 0) {
            return uri.substring(0, index);
        } else {
            return uri;
        }
    }
}
