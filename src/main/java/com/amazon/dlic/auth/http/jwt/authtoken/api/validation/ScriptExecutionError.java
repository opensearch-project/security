package com.amazon.dlic.auth.http.jwt.authtoken.api.validation;

import java.io.IOException;

import org.apache.logging.log4j.util.Strings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.script.ScriptException;

public class ScriptExecutionError extends ValidationError {

    private String context;

    public ScriptExecutionError(String attribute, ScriptException scriptException) {
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
        if ("runtime error".equals(scriptException.getMessage())) {
            if (scriptException.getCause() != null) {
                return constructMessage(scriptException.getCause());
            } else {
                return "Runtime Error";
            }
        } else {
            return constructMessage(scriptException);
        }
    }

    private static String constructMessage(Throwable throwable) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < 10; i++) {
            String message = throwable.getMessage();

            if (message == null) {
                message = throwable.toString();
            }

            if (result.indexOf(message) == -1) {
                if (result.length() != 0) {
                    result.append(":\n");
                }

                result.append(message);
            }

            if (throwable.getCause() == throwable || throwable.getCause() == null) {
                break;
            }

            throwable = throwable.getCause();
        }

        return result.toString();
    }

}


