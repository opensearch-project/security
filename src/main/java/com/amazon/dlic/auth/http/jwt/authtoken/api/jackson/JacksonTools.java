package com.amazon.dlic.auth.http.jwt.authtoken.api.jackson;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.BooleanNode;
import com.fasterxml.jackson.databind.node.ContainerNode;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.LongNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.NumericNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;


public class JacksonTools {
    public static Map<String, Object> toMap(JsonNode jsonNode) {
        if (jsonNode == null) {
            return null;
        } else if (jsonNode instanceof ObjectNode) {
            ObjectNode objectNode = (ObjectNode) jsonNode;
            Map<String, Object> result = new LinkedHashMap<>(objectNode.size());
            Iterator<Map.Entry<String, JsonNode>> iter = objectNode.fields();

            while (iter.hasNext()) {
                Map.Entry<String, JsonNode> field = iter.next();

                result.put(field.getKey(), toObject(field.getValue()));
            }

            return result;
        } else {
            Map<String, Object> result = new LinkedHashMap<>(1);

            result.put("_value", toObject(jsonNode));

            return result;
        }
    }

    public static Object toObject(JsonNode jsonNode) {
        if (jsonNode == null) {
            return null;
        } else if (jsonNode instanceof ObjectNode) {
            return toMap(jsonNode);
        } else if (jsonNode instanceof ArrayNode) {
            ArrayNode arrayNode = (ArrayNode) jsonNode;
            List<Object> result = new ArrayList<>(arrayNode.size());

            for (JsonNode child : arrayNode) {
                result.add(toObject(child));
            }

            return result;
        } else if (jsonNode instanceof NullNode) {
            return null;
        } else if (jsonNode instanceof IntNode) {
            return ((NumericNode) jsonNode).asInt();
        } else if (jsonNode instanceof LongNode) {
            return ((NumericNode) jsonNode).asLong();
        } else if (jsonNode instanceof NumericNode) {
            return ((NumericNode) jsonNode).asDouble();
        } else if (jsonNode instanceof BooleanNode) {
            return ((BooleanNode) jsonNode).asBoolean();
        } else if (jsonNode instanceof TextNode) {
            return ((TextNode) jsonNode).asText();
        } else {
            return jsonNode.toString();
        }
    }

    public static List<String> toStringArray(JsonNode jsonNode) {
        if (jsonNode instanceof ContainerNode) {
            List<String> result = new ArrayList<>(jsonNode.size());

            for (JsonNode member : jsonNode) {
                result.add(member.asText());
            }

            return result;
        } else if (jsonNode != null) {
            return Collections.singletonList(jsonNode.asText());
        } else {
            return Collections.emptyList();
        }
    }
}
