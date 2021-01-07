package com.amazon.dlic.auth.http.jwt.authtoken.api.exception;

import com.amazon.dlic.auth.http.jwt.authtoken.api.config.ConfigVersion;
import com.amazon.dlic.auth.http.jwt.authtoken.api.config.ConfigVersionSet;

public class UnknownConfigVersionException extends Exception {

    private static final long serialVersionUID = 7447114840568794908L;

    public UnknownConfigVersionException(ConfigVersion configurationVersion) {
        super("Configuration version " + configurationVersion + " is not stored");
    }

    public UnknownConfigVersionException(ConfigVersionSet configurationVersions) {
        super("Configuration versions " + configurationVersions + " are not stored");
    }
}

