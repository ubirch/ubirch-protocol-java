/*
 * Copyright (c) 2019 ubirch GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ubirch.protocol.codec;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import org.apache.commons.codec.binary.Hex;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePackException;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.jackson.dataformat.MessagePackFactory;
import org.msgpack.value.ValueType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

import static com.ubirch.protocol.codec.DecoderUtil.decodePayload;
import static com.ubirch.protocol.codec.ProtocolHints.HASHED_TRACKLE_MSG_PACK_HINT;

/**
 * The default msgpack ubirch protocol decoder.
 *
 * @author Matthias L. Jugel
 */
public class MsgPackProtocolDecoder extends ProtocolDecoder<byte[]> {
    private static final int PAYLOAD_OFFSET = 2;
    private final static MsgPackProtocolDecoder instance = new MsgPackProtocolDecoder();

    public static MsgPackProtocolDecoder getDecoder() {
        return instance;
    }

    private ObjectMapper mapper;

    @SuppressWarnings("WeakerAccess")
    MsgPackProtocolDecoder() {
        mapper = new ObjectMapper(new MessagePackFactory());
        mapper.configure(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS, true);
    }

    /**
     * Decode a protocol message from it's raw data.
     *
     * @param message the raw protocol message in msgpack format
     * @return the decoded protocol message
     * @throws ProtocolException if the decoding failed
     */
    @SuppressWarnings("checkstyle:FallThrough")
    @Override
    public ProtocolMessage decode(byte[] message) throws ProtocolException {
        boolean legacyPayloadDecoding = false;
        ByteArrayInputStream in = new ByteArrayInputStream(message);
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(in);
        ProtocolMessage pm = new ProtocolMessage();
        try {
            ValueType envelopeType = unpacker.getNextFormat().getValueType();
            int envelopeLength = unpacker.unpackArrayHeader();
            if (envelopeLength > 4 && envelopeLength < 7) {
                pm.setVersion(unpacker.unpackInt());

                int protocolVersion = pm.getVersion() >> 4;
                switch (protocolVersion) {
                    case 1:
                        legacyPayloadDecoding = true;
                    case ProtocolMessage.ubirchProtocolVersion:
                        break;
                    default:
                        throw new ProtocolException(String.format("unknown protocol version: %d", protocolVersion));
                }

                pm.setUUID(UUIDUtil.bytesToUUID(unpacker.readPayload(unpacker.unpackRawStringHeader())));
                switch (pm.getVersion() & 0x0F) {
                    case ProtocolMessage.CHAINED & 0x0F:
                        pm.setChain(unpacker.readPayload(unpacker.unpackRawStringHeader()));
                        break;
                    case ProtocolMessage.SIGNED & 0x0F:
                        break;
                    default:
                        throw new ProtocolException(String.format("unknown protocol type: 0x%04x", pm.getVersion() & 0x0F));
                }
                pm.setHint(unpacker.unpackInt());
                if (!legacyPayloadDecoding) {
                    pm.setPayload(mapper.readTree(message).get(envelopeLength - PAYLOAD_OFFSET));
                    unpacker.skipValue();
                } else {
                    pm.setPayload(decodePayload(unpacker));
                }

                // finally store the signed data and signature for later verification
                if (pm.getHint() == HASHED_TRACKLE_MSG_PACK_HINT) {
                    // in hashed trackle msg packs the payload contains the signed SHA-512 hash
                    pm.setSigned(pm.getPayload().binaryValue());
                } else {
                    // in all other UPPs all bytes including the payload except for the signature are signed
                    pm.setSigned(Arrays.copyOfRange(message, 0, (int) unpacker.getTotalReadBytes()));
                }
                pm.setSignature(unpacker.readPayload(unpacker.unpackRawStringHeader()));
                return pm;
            } else {
                throw new ProtocolException(String.format("unknown msgpack envelope format: %s[%d]", envelopeType.name(), envelopeLength));
            }
        } catch (MessagePackException e) {
            throw new ProtocolException("msgpack decoding failed", e);
        } catch (IOException e) {
            throw new ProtocolException(String.format("msgpack data corrupt at position %d", unpacker.getTotalReadBytes()), e);
        }
    }

    public boolean isHashedTrackleMsgType(byte[] message) {
        if (message.length > 133) {
            byte[] hint = Arrays.copyOfRange(message, message.length - 133, message.length - 132);
            return Hex.encodeHexString(hint).equals(Integer.toHexString(HASHED_TRACKLE_MSG_PACK_HINT));
        } else {
            return false;
        }
    }

    /**
     * Extracts the signed part and the signature out of the message pack without materializing the other fields
     * of the msgPack.
     *
     * @param message the raw protocol message in msgpack format
     * @return an array of arrays where the first element is the signed data and the second element is the signature.
     * @throws ProtocolException if the fast extraction fails
     */
    public byte[][] getDataToVerifyAndSignature(byte[] message) throws ProtocolException {
        ByteArrayInputStream in = new ByteArrayInputStream(message);
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(in);

        try {

            ValueType envelopeType = unpacker.getNextFormat().getValueType();
            int envelopeLength = unpacker.unpackArrayHeader();
            if (envelopeLength > 4 && envelopeLength < 7) {

                //We skip through the values up to the signature.
                for (int i = 0; i < envelopeLength - 3; i++) {
                    unpacker.skipValue();
                }

                byte[] signedBytes;
                if (unpacker.unpackInt() == HASHED_TRACKLE_MSG_PACK_HINT) {
                    // in hashed trackle msg packs the payload contains the signed SHA-512 hash
                    int length = unpacker.unpackBinaryHeader();
                    signedBytes = unpacker.readPayload(length);
                } else {
                    // in all other UPPs all bytes including the payload except for the signature are signed
                    unpacker.skipValue();
                    signedBytes = Arrays.copyOfRange(message, 0, (int) unpacker.getTotalReadBytes());
                }

                byte[] signatureBytes = unpacker.readPayload(unpacker.unpackRawStringHeader());

                return new byte[][]{signedBytes, signatureBytes};
            } else {
                throw new ProtocolException(String.format("unknown msgpack envelope format: %s[%d]", envelopeType.name(), envelopeLength));
            }
        } catch (MessagePackException e) {
            throw new ProtocolException("msgpack decoding failed", e);
        } catch (IOException e) {
            throw new ProtocolException(String.format("msgpack data corrupt at position %d", unpacker.getTotalReadBytes()), e);
        }
    }

}
