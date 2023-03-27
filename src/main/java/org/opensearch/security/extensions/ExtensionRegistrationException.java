package org.opensearch.security.extensions;

public class ExtensionRegistrationException extends Exception {

    public ExtensionRegistrationException() {
        super();
    }

    public ExtensionRegistrationException(String message, Throwable cause, boolean enableSuppression,
                                   boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public ExtensionRegistrationException(String message, Throwable cause) {
        super(message, cause);
    }

    public ExtensionRegistrationException(String message) {
        super(message);
    }

    public ExtensionRegistrationException(Throwable cause) {
        super(cause);
    }
}
