package com.amazon.dlic.auth.http.jwt.authtoken.api.validation;

import java.io.IOException;

import org.apache.logging.log4j.util.Strings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.script.ScriptException;

public class ScriptValidationError extends ValidationError {

    private String context;

    public ScriptValidationError(String attribute, ScriptException scriptException) {
        super(attribute, getMessage(scriptException));
        cause(scriptException);

        if (scriptException.getScriptStack() != null && scriptException.getScriptStack().size() > 0) {
            context = Strings.join(scriptException.getScriptStack(), '\n');
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("error", getMessage());

        if (context != null) {
            builder.field("context", context);
        }

        builder.endObject();
        return builder;
    }

    private static String getMessage(ScriptException scriptException) {
        if ("compile error".equals(scriptException.getMessage())) {
            if (scriptException.getCause() != null) {
                return scriptException.getCause().getMessage();
            } else {
                return "Compilation Error";
            }
        } else {
            return scriptException.getMessage();
        }
    }
}