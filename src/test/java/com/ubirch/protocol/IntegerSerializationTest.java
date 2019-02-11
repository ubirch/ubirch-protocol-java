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

package com.ubirch.protocol;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ubirch.protocol.codec.JSONProtocolDecoder;
import com.ubirch.protocol.codec.JSONProtocolEncoder;
import com.ubirch.protocol.codec.MsgPackProtocolDecoder;
import com.ubirch.protocol.codec.MsgPackProtocolEncoder;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

import static com.ubirch.protocol.ProtocolMessage.CHAINED;
import static com.ubirch.protocol.ProtocolMessage.SIGNED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test serialization of integers with different sizes.
 *
 * @author Matthias L. Jugel
 */

class IntegerSerializationTest extends ProtocolFixtures {
    private static final UUID TEST_UUID = UUID.fromString("00000000-0000-0000-0000-000000000000");
    private final Logger logger = LoggerFactory.getLogger(IntegerSerializationTest.class);

    @Test
    void testJSONIntSerialization() throws SignatureException, ProtocolException {
        ProtocolMessage pm = new ProtocolMessage(SIGNED, TEST_UUID, 0x22,
                new int[] { Integer.MIN_VALUE, Integer.MAX_VALUE });
        JSONProtocolEncoder encoder = JSONProtocolEncoder.getEncoder();
        String message = encoder.encode(pm, (uuid, data, offset, len) -> new byte[64]);

        ProtocolMessage decodedMessage = JSONProtocolDecoder.getDecoder().decode(message);
        assertEquals(Integer.MIN_VALUE, decodedMessage.getPayload().get(0).asInt());
        assertEquals(Integer.MAX_VALUE, decodedMessage.getPayload().get(1).asInt());
    }

    @Test
    void testJSONLongSerialization() throws SignatureException, ProtocolException {
        ProtocolMessage pm = new ProtocolMessage(SIGNED, TEST_UUID, 0x22,
                new Long[] { Long.MIN_VALUE, Long.MAX_VALUE });
        JSONProtocolEncoder encoder = JSONProtocolEncoder.getEncoder();
        String message = encoder.encode(pm, (uuid, data, offset, len) -> new byte[64]);
        logger.debug(message);

        ProtocolMessage decodedMessage = JSONProtocolDecoder.getDecoder().decode(message);
        assertEquals(Long.MIN_VALUE, decodedMessage.getPayload().get(0).asLong());
        assertEquals(Long.MAX_VALUE, decodedMessage.getPayload().get(1).asLong());
    }

    @Test
    void testJSONBigIntegerSerialization() throws SignatureException, ProtocolException {
        BigInteger value = new BigInteger(64, new Random());
        ProtocolMessage pm = new ProtocolMessage(SIGNED, TEST_UUID, 0x22, value);
        JSONProtocolEncoder encoder = JSONProtocolEncoder.getEncoder();
        String message = encoder.encode(pm, (uuid, data, offset, len) -> new byte[64]);

        ProtocolMessage decodedMessage = JSONProtocolDecoder.getDecoder().decode(message);
        assertEquals(value, decodedMessage.getPayload().bigIntegerValue());
    }

    @Test
    void testMsgPackIntSerialization() throws SignatureException, ProtocolException {
        ProtocolMessage pm = new ProtocolMessage(SIGNED, TEST_UUID, 0x22,
                new int[] { Integer.MIN_VALUE, Integer.MAX_VALUE });
        MsgPackProtocolEncoder encoder = MsgPackProtocolEncoder.getEncoder();
        byte[] message = encoder.encode(pm, (uuid, data, offset, len) -> new byte[64]);

        ProtocolMessage decodedMessage = MsgPackProtocolDecoder.getDecoder().decode(message);
        assertEquals(Integer.MIN_VALUE, decodedMessage.getPayload().get(0).asInt());
        assertEquals(Integer.MAX_VALUE, decodedMessage.getPayload().get(1).asInt());
    }

    @Test
    void testMsgPackLongSerialization() throws SignatureException, ProtocolException {
        ProtocolMessage pm = new ProtocolMessage(SIGNED, TEST_UUID, 0x22,
                new Long[] { Long.MIN_VALUE, Long.MAX_VALUE });
        MsgPackProtocolEncoder encoder = MsgPackProtocolEncoder.getEncoder();
        byte[] message = encoder.encode(pm, (uuid, data, offset, len) -> new byte[64]);

        ProtocolMessage decodedMessage = MsgPackProtocolDecoder.getDecoder().decode(message);
        assertEquals(Long.MIN_VALUE, decodedMessage.getPayload().get(0).asLong());
        assertEquals(Long.MAX_VALUE, decodedMessage.getPayload().get(1).asLong());
    }

    @Test
    void testMsgPackBigIntegerSerialization() throws SignatureException, ProtocolException {
        BigInteger value = new BigInteger(64, new Random());
        ProtocolMessage pm = new ProtocolMessage(SIGNED, TEST_UUID, 0x22, value);
        MsgPackProtocolEncoder encoder = MsgPackProtocolEncoder.getEncoder();
        byte[] message = encoder.encode(pm, (uuid, data, offset, len) -> new byte[64]);

        ProtocolMessage decodedMessage = MsgPackProtocolDecoder.getDecoder().decode(message);
        assertEquals(value, decodedMessage.getPayload().bigIntegerValue());
    }

}
