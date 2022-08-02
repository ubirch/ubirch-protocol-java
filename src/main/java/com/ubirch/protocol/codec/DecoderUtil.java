package com.ubirch.protocol.codec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import org.msgpack.core.ExtensionTypeHeader;
import org.msgpack.core.MessageFormat;
import org.msgpack.core.MessageNeverUsedFormatException;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.value.ImmutableStringValue;
import org.msgpack.value.ValueFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DecoderUtil {

    private DecoderUtil() {
        //not called
    }

    /**
     * This method analyzes of what type the payload field is and retrieves the value as a JsonNode.
     * This JsonNode can be of different types, e.g. BooleanNode, BinaryNode, TextNode, ...
     */
    public static JsonNode decodePayload(MessageUnpacker unpacker) throws IOException {
        MessageFormat mf = unpacker.getNextFormat();
        switch (mf.getValueType()) {
            case NIL:
                unpacker.unpackNil();
                return NullNode.getInstance();
            case BOOLEAN:
                return BooleanNode.valueOf(unpacker.unpackBoolean());
            case INTEGER:
                if (mf == MessageFormat.UINT64) {
                    return BigIntegerNode.valueOf(unpacker.unpackBigInteger());
                }
                return LongNode.valueOf(unpacker.unpackLong());
            case FLOAT:
                return DoubleNode.valueOf(unpacker.unpackDouble());
            case STRING: {
                int length = unpacker.unpackRawStringHeader();
                ImmutableStringValue stringValue = ValueFactory.newString(unpacker.readPayload(length), true);
                if (stringValue.isRawValue()) {
                    return BinaryNode.valueOf(stringValue.asRawValue().asByteArray());
                } else {
                    return TextNode.valueOf(stringValue.asString());
                }
            }
            case BINARY: {
                int length = unpacker.unpackBinaryHeader();
                return BinaryNode.valueOf(unpacker.readPayload(length));
            }
            case ARRAY: {
                int size = unpacker.unpackArrayHeader();
                List<JsonNode> array = new ArrayList<>(size);
                for (int i = 0; i < size; i++) {
                    array.add(decodePayload(unpacker));
                }
                return new ArrayNode(null, array);
            }
            case MAP: {
                int size = unpacker.unpackMapHeader();
                Map<String, JsonNode> kvs = new HashMap<>(size);
                for (int i = 0; i < size; i++) {
                    JsonNode kn = decodePayload(unpacker);
                    String key = kn.isBinary() ? new String(kn.binaryValue()) : kn.asText();
                    kvs.put(key, decodePayload(unpacker));
                }
                return new ObjectNode(null, kvs);
            }
            case EXTENSION: {
                ExtensionTypeHeader extHeader = unpacker.unpackExtensionTypeHeader();
                return BinaryNode.valueOf(unpacker.readPayload(extHeader.getLength()));
            }
            default:
                throw new MessageNeverUsedFormatException("Unknown value type");
        }
    }
}
