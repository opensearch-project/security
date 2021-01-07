package com.amazon.dlic.auth.http.jwt.authtoken.api;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.google.common.base.Joiner;
import com.google.common.collect.Iterables;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.InvalidPathException;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;

public class UserAttributes {

    private static final Logger log = LogManager.getLogger(UserAttributes.class);
    private static final JsonFactory JSON_FACTORY = new JsonFactory();
    private static final Configuration JSON_PATH_CONFIG = Configuration.defaultConfiguration().setOptions(Option.SUPPRESS_EXCEPTIONS);

    public static Map<String, JsonPath> getAttributeMapping(Settings settings) {
        HashMap<String, JsonPath> result = new HashMap<>();

        if (settings == null) {
            return result;
        }

        for (String key : settings.keySet()) {
            try {
                result.put(key, JsonPath.compile(settings.get(key)));
            } catch (InvalidPathException e) {
                log.error("Error in configuration: Invalid JSON path supplied for " + key, e);
            }
        }

        return result;
    }

    public static Map<String, String> getFlatAttributeMapping(Settings settings) {
        HashMap<String, String> result = new HashMap<>();

        if (settings == null) {
            return result;
        }
        for (String key : settings.keySet()) {
            result.put(key, settings.get(key));
        }

        return result;
    }

    public static String replaceAttributes(String string, User user) throws Exception {

        return new StringAttributeInterpolator(string, user).process();
    }

    public static void validate(Object value) {
        validate(value, 0);
    }

    public static void addAttributesByJsonPath(Map<String, JsonPath> jsonPathMap, Object source, Map<String, Object> target) {
        for (Map.Entry<String, JsonPath> entry : jsonPathMap.entrySet()) {
            Object values = JsonPath.using(JSON_PATH_CONFIG).parse(source).read(entry.getValue());
            try {
                UserAttributes.validate(values);
            } catch (IllegalArgumentException e) {
                throw new ElasticsearchSecurityException(
                        "Error while initializing user attributes. Mapping for " + entry.getKey() + " produced invalid values:\n" + e.getMessage(),
                        e);
            }

            target.put(entry.getKey(), values);
        }
    }

    private static void validate(Object value, int depth) {
        if (depth > 10) {
            throw new IllegalArgumentException("Value exceeds max allowed nesting (or the value contains loops)");
        }

        if (value == null) {
            return;
        } else if (value instanceof String || value instanceof Number || value instanceof Boolean || value instanceof Character) {
            return;
        } else if (value instanceof Collection) {
            for (Object element : ((Collection<?>) value)) {
                validate(element, depth + 1);
            }
        } else if (value instanceof Map) {
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                validate(entry.getKey(), depth + 1);
                validate(entry.getValue(), depth + 1);
            }
        } else {
            throw new IllegalArgumentException(
                    "Illegal value type. In user attributes the only allowed types are: String, Number, Boolean, Character, Collection, Map. Got: "
                            + value);
        }
    }

    private static String toQuotedCommaSeparatedString(Collection<?> values) {
        return Joiner.on(',').join(Iterables.transform(values, s -> '"' + String.valueOf(s).replaceAll("\"", "\\\"") + '"'));
    }

    private static List<?> tail(Collection<?> collection) {
        if (collection.size() <= 1) {
            return Collections.emptyList();
        }

        List<Object> result = new ArrayList<>(collection.size() - 1);

        Iterator<?> iter = collection.iterator();
        iter.next();

        while (iter.hasNext()) {
            result.add(iter.next());
        }

        return result;
    }

    static class StringAttributeInterpolator {
        private final String string;
        private final User user;
        private int i = 0;

        StringAttributeInterpolator(String source, User user) {
            this.string = source;
            this.user = user;
        }

        String process() throws Exception {

            StringBuilder result = new StringBuilder();

            for (;;) {
                int openBracket = string.indexOf("${", i);
                if (openBracket == -1) {
                    if (i < string.length()) {
                        result.append(string.substring(i));
                    }
                    break;
                } else {
                    result.append(string.substring(i, openBracket));

                    i = openBracket;

                    String replacement = processAttribute();

                    result.append(replacement);
                }
            }

            return result.toString();
        }

        private String processAttribute() throws Exception {

            int openBracket = i;

            String attributeName = readAttributeName(openBracket);
            Object value = getAttributeValue(attributeName, openBracket);
            skipSpaces();

            for (;;) {
                if (i >= string.length()) {
                    throw new Exception("Unclosed attribute at " + openBracket + ":\n" + string);
                }

                char c = string.charAt(i);
                char c2 = i < string.length() - 1 ? string.charAt(i + 1) : 0;

                if (c == '|') {
                    i++;
                    skipSpaces();
                    int functionStart = i;
                    String functionName = readFunctionName(openBracket);
                    value = evaluateFunction(functionName, value, functionStart);
                } else if (c == '?' && c2 == ':') {
                    i += 2;
                    skipSpaces();
                    Object defaultValue = readJson(i);

                    if (value == null) {
                        value = defaultValue;
                    }
                } else if (c == ':' && c2 == '-') {
                    i += 2;
                    int closeBracket = string.indexOf('}', i);

                    if (closeBracket == -1) {
                        throw new Exception("Unclosed attribute at " + openBracket + ":\n" + string);
                    }

                    String defaultValue = string.substring(i, closeBracket);

                    if (value == null) {
                        value = defaultValue;
                    }

                    i = closeBracket;

                } else if (c == '}') {
                    i++;
                    break;
                } else if (Character.isWhitespace(c)) {
                    skipSpaces();
                } else {
                    throw new Exception("Unexpected character " + c + " at " + i + ":\n" + string);
                }

            }

            if (value == null) {
                throw new Exception("No value set for " + attributeName);
            }

            if (value instanceof Collection) {
                value = toQuotedCommaSeparatedString((Collection<?>) value);
            } else if (!(value instanceof String)) {
                value = value.toString();
            }

            return (String) value;
        }

        private String readAttributeName(int openBracket) throws Exception {
            for (i += 2;; i++) {
                if (i >= string.length()) {
                    throw new Exception("Unclosed attribute at " + openBracket + ":\n" + string);
                }

                char c = string.charAt(i);

                if (!Character.isLetter(c) && !Character.isDigit(c) && c != '.' && c != '_') {
                    String attributeName = string.substring(openBracket + 2, i);

                    return attributeName;
                }
            }
        }

        private String readFunctionName(int openBracket) throws Exception {
            int functionStart = i;

            for (i += 2;; i++) {
                if (i >= string.length()) {
                    throw new Exception("Unclosed attribute at " + openBracket + ":\n" + string);
                }

                char c = string.charAt(i);

                if (!Character.isLetter(c)) {
                    String functionName = string.substring(functionStart, i);

                    return functionName;
                }
            }
        }

        private Object evaluateFunction(String operation, Object value, int stateStart) throws Exception {
            if (value != null) {
                if (operation.equals("toString")) {
                    value = value.toString();
                } else if (operation.equals("toJson")) {
                    value = BasicJsonWriter.writeAsString(value);
                } else if (operation.equals("toList")) {
                    if (!(value instanceof Collection)) {
                        value = Collections.singletonList(value);
                    }
                } else if (operation.equals("head")) {
                    if (value instanceof Collection) {
                        value = Iterables.getFirst((Collection<?>) value, null);
                    }
                } else if (operation.equals("tail")) {
                    if (value instanceof Collection) {
                        value = tail((Collection<?>) value);
                    } else {
                        value = Collections.emptyList();
                    }
                } else if (operation.equals("toRegexFragment")) {
                    value = toRegexFragment(value);
                } else {
                    throw new Exception(
                            "Unsupported operation " + operation + " in string template at index " + stateStart + ": " + string);
                }
            }

            return value;
        }

        @SuppressWarnings("deprecation")
        private Object getAttributeValue(String attributeName, int openBracket) throws Exception {
            if (attributeName.equals("user.name") || attributeName.equals("user_name")) {
                return user.getName();
            } else if (attributeName.equals("user.roles") || attributeName.equals("user_roles")) {
                return user.getRoles();
            } else if (attributeName.equals("user.attrs")) {
                return user.getStructuredAttributes();
            } else if (attributeName.startsWith("user.attrs.")) {
                return user.getStructuredAttributes().get(attributeName.substring("user.attrs.".length()));
            } else if (attributeName.startsWith("attr.") || attributeName.startsWith("_")) {
                log.warn("The attribute ${" + attributeName + "} could not be mapped to a value. "
                        + "For backwards compatibility, the resulting string will contain the unmapped attribute unchanged. "
                        + "You should consider changing the configuration to the new Search Guard user attributes which provide default values for this case. "
                        + "The old attribute syntax will be removed in a future major Search Guard release.\n" + "Complete String: " + string
                        + "\nAvailable attributes: " + user.getCustomAttributesMap().keySet());
                return "${" + attributeName + "}";
            } else {
                throw new Exception("Invalid attribute name " + attributeName + " at index " + openBracket + ": " + string);
            }
        }

        private void skipSpaces() {
            for (;;) {
                if (i < string.length() && Character.isSpaceChar(string.charAt(i))) {
                    i++;
                } else {
                    break;
                }
            }
        }

        private Object readJson(int start) throws Exception {
            try {
                JsonParser parser = JSON_FACTORY.createParser(string.substring(start));

                Object result = BasicJsonReader.read(parser);

                i = start + (int) parser.getTokenLocation().getCharOffset() + parser.getLastClearedToken().asString().length();

                if (log.isTraceEnabled()) {
                    log.trace("readJson " + start + " => " + i + ": " + result);
                }
                return result;

            } catch (IOException e) {
                throw new Exception("Invalid JSON block at " + start + ": " + string, e);
            }
        }

        private String toRegexFragment(Object value) {
            if (value == null) {
                return null;
            } else if (value instanceof Collection) {
                StringBuilder result = new StringBuilder("(");
                boolean first = true;

                for (Object element : (Collection<?>) value) {
                    if (element != null) {
                        if (!first) {
                            result.append("|");
                        } else {
                            first = false;
                        }

                        result.append(Pattern.quote(element.toString()));
                    }
                }

                result.append(")");

                return result.toString();
            } else {
                return "(" + Pattern.quote(value.toString()) + ")";
            }
        }
    }

}

