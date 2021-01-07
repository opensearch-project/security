package com.amazon.dlic.auth.http.jwt.authtoken.api.elements;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptException;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.script.ScriptType;
import org.elasticsearch.script.TemplateScript;

import com.google.common.base.Functions;

public class InlineMustacheTemplate<ResultType> implements ToXContent {
    private final static Logger log = LogManager.getLogger(InlineMustacheTemplate.class);

    private String source;
    private ResultType parsedConstantValue;
    private boolean constant = false;
    private ValidatingFunction<String, ResultType> conversionFunction;
    private TemplateScript.Factory factory;
    private Object expectedValue;

    private InlineMustacheTemplate(String source, ValidatingFunction<String, ResultType> conversionFunction, Object expectedValue) {
        this.source = source;
        this.conversionFunction = conversionFunction;
        this.expectedValue = expectedValue;
    }

    private InlineMustacheTemplate(ResultType constant) {
        this.parsedConstantValue = constant;
        this.constant = true;
    }

    private void compile(ScriptService scriptService, ValidationErrors validationErrors) {
        if (this.source == null || !this.source.contains("{{")) {
            this.constant = true;
            try {
                this.parsedConstantValue = this.conversionFunction.apply(this.source);
            } catch (Exception e) {
                validationErrors.add(new InvalidAttributeValue(null, this.source, expectedValue).cause(e));
            }
            return;
        }

        Script script = new Script(ScriptType.INLINE, Script.DEFAULT_TEMPLATE_LANG, source, Collections.emptyMap());

        try {
            this.factory = scriptService.compile(script, TemplateScript.CONTEXT);
        } catch (ScriptException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while compiling script " + script, e);
            }

            validationErrors.add(new ScriptValidationError(null, e));
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        if (constant) {
            builder.value(String.valueOf(parsedConstantValue));
        } else {
            builder.value(source);
        }
        return builder;
    }

    public TemplateScript.Factory getFactory() {
        return factory;
    }

    public String render(Map<String, Object> params) throws ScriptException {
        if (factory != null) {
            return factory.newInstance(params).execute();
        } else if (constant) {
            return source;
        } else {
            return null;
        }
    }

    public ResultType get(Map<String, Object> params) throws ConfigValidationException {
        if (constant) {
            return parsedConstantValue;
        }

        String value = null;

        try {
            value = render(params);
        } catch (ScriptException e) {
            throw new ConfigValidationException(new ScriptExecutionError(null, e));
        }

        if (value != null) {
            try {
                return this.conversionFunction.apply(value);
            } catch (IllegalArgumentException e) {
                throw new ConfigValidationException(new InvalidAttributeValue(null, value, expectedValue));
            } catch (Exception e) {
                throw new ConfigValidationException(new ValidationError(null, value));
            }
        } else {
            return null;
        }
    }

    public ResultType get(Map<String, Object> params, String attribute, ValidationErrors validationErrors) {
        try {
            return get(params);
        } catch (ConfigValidationException e) {
            validationErrors.add(attribute, e);
            return null;
        }
    }

    public boolean isConstant() {
        return constant;
    }

    public ResultType getConstant() {
        return parsedConstantValue;
    }

    public static <ResultType> InlineMustacheTemplate<ResultType> parse(ScriptService scriptService, String value,
                                                                        Function<String, ResultType> conversionFunction) throws ConfigValidationException {
        return parse(scriptService, value, conversionFunction, null);
    }

    public static <ResultType> InlineMustacheTemplate<ResultType> parse(ScriptService scriptService, String value,
                                                                        Function<String, ResultType> conversionFunction, Object expectedValue) throws ConfigValidationException {
        return parse(scriptService, value, ValidatingFunction.from(conversionFunction), expectedValue);
    }

    public static <ResultType> InlineMustacheTemplate<ResultType> parse(ScriptService scriptService, String value,
                                                                        ValidatingFunction<String, ResultType> conversionFunction) throws ConfigValidationException {
        return parse(scriptService, value, conversionFunction, null);
    }

    public static <ResultType> InlineMustacheTemplate<ResultType> parse(ScriptService scriptService, String value,
                                                                        ValidatingFunction<String, ResultType> conversionFunction, Object expectedValue) throws ConfigValidationException {
        ValidationErrors validationErrors = new ValidationErrors();
        InlineMustacheTemplate<ResultType> result = new InlineMustacheTemplate<ResultType>(value, conversionFunction, expectedValue);

        result.compile(scriptService, validationErrors);
        validationErrors.throwExceptionForPresentErrors();
        return result;
    }

    public static InlineMustacheTemplate<String> parse(ScriptService scriptService, String value) throws ConfigValidationException {
        return parse(scriptService, value, Functions.identity());
    }

    public static <ResultType> InlineMustacheTemplate<ResultType> constant(ResultType value) {
        return value != null ? new InlineMustacheTemplate<ResultType>(value) : null;
    }

    public static class Parser<ResultType> implements ValueParser<InlineMustacheTemplate<ResultType>> {
        private final ScriptService scriptService;
        private final Function<String, ResultType> conversionFunction;

        public Parser(ScriptService scriptService, Function<String, ResultType> conversionFunction) {
            this.scriptService = scriptService;
            this.conversionFunction = conversionFunction;
        }

        @Override
        public InlineMustacheTemplate<ResultType> parse(String string) throws ConfigValidationException {
            return InlineMustacheTemplate.parse(scriptService, string, conversionFunction);
        }

        @Override
        public String getExpectedValue() {
            return "Mustache Template";
        }
    }
}

