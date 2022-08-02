package com.ubirch.protocol.codec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import org.msgpack.core.MessagePacker;
import org.msgpack.jackson.dataformat.MessagePackFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

public final class EncoderUtil {

    private EncoderUtil() {
        //not called
    }

    public static void packVersion(MessagePacker packer, ProtocolMessage pm) throws IOException {
        packer.packInt(pm.getVersion());
    }

    public static void packUUID(MessagePacker packer, ProtocolMessage pm) throws IOException {
        packer.packBinaryHeader(16).addPayload(UUIDUtil.uuidToBytes(pm.getUUID()));
    }

    public static void packChain(MessagePacker packer, ProtocolMessage pm) throws IOException {
        switch (pm.getVersion()) {
            case ProtocolMessage.CHAINED:
                packer.packBinaryHeader(64);
                byte[] chainSignature = pm.getChain();
                if (chainSignature == null) {
                    packer.addPayload(new byte[64]);
                } else {
                    packer.addPayload(chainSignature);
                }
                break;
            case ProtocolMessage.SIGNED:
                break;
            default:
                throw new ProtocolException(String.format("unknown protocol version: 0x%x", pm.getVersion()));
        }
    }

    public static void packHint(MessagePacker packer, ProtocolMessage pm) throws IOException {
        packer.packInt(pm.getHint());
    }

    /**
     * This method packs the msgPack depending on the JsonNode type.
     */
    public static void packPayload(MessagePacker packer, ProtocolMessage pm, ByteArrayOutputStream out) throws IOException {
        // https://gitlab.com/ubirch/ubirch-kafka-envelope/-/blob/master/src/main/scala/com/ubirch/kafka/package.scala#L166
        // json4s
        // ------
        // To be able to return the payload as just bytes and not as base64 values, we have to
        // explicitly try to decode and pack the data in the msgpack.
        // There seems to be a limitation with the way json4s handles binary nodes.
        // https://gitlab.com/ubirch/ubirch-kafka-envelope/-/blob/master/src/main/scala/com/ubirch/kafka/package.scala#L166
        if (pm.getPayload() instanceof BinaryNode) {
            packer.packBinaryHeader(pm.getPayload().binaryValue().length);
            packer.writePayload(pm.getPayload().binaryValue());
        } else if (pm.getPayload() instanceof TextNode) {
            try {
                byte[] bytes = Base64.getDecoder().decode(pm.getPayload().asText());
                packer.packBinaryHeader(bytes.length).addPayload(bytes);
            } catch (Exception e)  {
                ObjectMapper mapper = new ObjectMapper(new MessagePackFactory());
                mapper.writeValue(out, pm.getPayload());
            }
        } else {
            ObjectMapper mapper = new ObjectMapper(new MessagePackFactory());
            mapper.writeValue(out, pm.getPayload());
        }
    }

}
