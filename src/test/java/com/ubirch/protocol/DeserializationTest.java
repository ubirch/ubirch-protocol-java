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
import com.ubirch.protocol.codec.MsgPackProtocolDecoder;
import com.ubirch.protocol.codec.UUIDUtil;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static com.ubirch.protocol.ProtocolMessage.CHAINED;
import static com.ubirch.protocol.ProtocolMessage.SIGNED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**k
 * Test deserialization of encoded messages already in production.
 *
 * @author Matthias L. Jugel
 */

class DeserializationTest extends ProtocolFixtures {
    private final Logger logger = LoggerFactory.getLogger(DeserializationTest.class);

    private static final UUID TEST_UUID = UUID.fromString("00000000-0000-0000-0000-000000000000");
    private static final UUID TEST_UUID_ECDSA = UUID.fromString("b99447f2-2114-4044-9eb9-f57759eab90e");
    private static final UUID TEST_UUID_ECDSA_V2 = UUID.fromString("b99447f2-2114-4044-9eb9-f57759eab91f");

    @Test
    void testDecodeTrackleMessage() throws IOException {
        byte[] message = getBinaryFixture("msgpack/v0.4-trackle-production.mpack");

        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        ProtocolMessage pm = decoder.decode(message);

        assertEquals(1, pm.version >> 4, "unexpected protocol version for trackle (v1) message");
        assertEquals(CHAINED & 0x0f, pm.version & 0x0f);
        assertEquals(UUID.fromString("af931b05-acca-758b-c2aa-eb98d6f93329"), pm.uuid);
        assertEquals(0x54, pm.hint);
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        JsonNode payload = pm.getPayload();
        assertEquals("v1.0.2-PROD-20180326103205 (v5.6.6)", new String(payload.get(0).binaryValue()));
        assertEquals(2766, payload.get(1).asInt());
        assertEquals(3, payload.get(2).asInt());

        // the original data contains a map of timestamp:temperature, so we need to map this type accordingly
        ObjectMapper mapper = new ObjectMapper();
        Map<Integer, Integer> values = mapper.convertValue(payload.get(3), new TypeReference<Map<Integer, Integer>>() {
        });
        // the actual data contains one duplicated timestamp (it contains 737 data points)
        assertEquals(736, values.size());
        assertEquals(3519, (int) values.get(1533846771));
        assertEquals(3914, (int) values.get(1537214378));
    }

    @Test
    void testDecodeKeyRegistrationMessage() throws IOException, DecoderException {

        byte[] message = getBinaryFixture("msgpack/v1.0-register.mpack");

        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        ProtocolMessage pm = decoder.decode(message);

        assertEquals(1, pm.version >> 4, "unexpected protocol version for v1 message");
        assertEquals(SIGNED & 0x0f, pm.version & 0x0f);
        assertEquals(TEST_UUID, pm.uuid);
        assertEquals(0x01, pm.hint);
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        JsonNode payload = pm.getPayload();
        byte[] expectedPubKey = Hex.decodeHex("2c37eee25b08490a9936e0c4d1f8f2091bebdbc3b08e29164e833a33742df91a".toCharArray());
        assertEquals("ECC_ED25519", new String(payload.get("algorithm").binaryValue(), StandardCharsets.UTF_8));
        assertEquals(1542793437, payload.get("created").asInt());
        assertEquals(16, payload.get("hwDeviceId").binaryValue().length);
        assertArrayEquals(new byte[16], payload.get("hwDeviceId").binaryValue());
        assertArrayEquals(expectedPubKey, payload.get("pubKey").binaryValue());
        assertArrayEquals(expectedPubKey, payload.get("pubKeyId").binaryValue());
        assertEquals(1574329437, payload.get("validNotAfter").asInt());
        assertEquals(1542793437, payload.get("validNotBefore").asInt());

        logger.debug("protocol message: " + new ObjectMapper().writeValueAsString(pm));
    }

    @Test
    void testDecodeMessageECDSAv1() throws IOException, NoSuchAlgorithmException {
        byte[] message = getBinaryFixture("msgpack/v1.0-ecdsa-message.mpack");

        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        ProtocolMessage pm = decoder.decode(message);

        assertEquals(1, pm.version >> 4, "unexpected protocol version for v1 message");
        assertEquals(SIGNED & 0x0f, pm.version & 0x0f);
        assertEquals(TEST_UUID_ECDSA, pm.uuid);
        assertEquals(0x00, pm.hint);
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        JsonNode payload = pm.getPayload();
        assertArrayEquals(
            MessageDigest.getInstance("SHA-256").digest("UBIRCH".getBytes()),
            Base64.getDecoder().decode(payload.asText()));
    }

    @Test
    void testDecodeKeyRegistrationMessageECDSAv1() throws IOException, DecoderException {

        byte[] message = getBinaryFixture("msgpack/v1.0-ecdsa-register.mpack");

        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        ProtocolMessage pm = decoder.decode(message);

        assertEquals(1, pm.version >> 4, "unexpected protocol version for v1 message");
        assertEquals(SIGNED & 0x0f, pm.version & 0x0f);
        assertEquals(TEST_UUID_ECDSA, pm.uuid);
        assertEquals(0x01, pm.hint);
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        JsonNode payload = pm.getPayload();
        byte[] expectedPubKey = Hex.decodeHex("06784eaaf180c1091a135bfe4804306f696fc56a4a75d12e269bfcafb67498d5a963fb72aaaca9fa3209bdf9b34d249c493bd5cd0a4d3763e425c8f461af50a5".toCharArray());
        assertEquals("ECDSHA_SHA_256", new String(payload.get("algorithm").binaryValue(), StandardCharsets.UTF_8));
        assertEquals(1550925476, payload.get("created").asInt());
        assertEquals(16, payload.get("hwDeviceId").binaryValue().length);
        assertArrayEquals(UUIDUtil.uuidToBytes(TEST_UUID_ECDSA), payload.get("hwDeviceId").binaryValue());
        assertArrayEquals(expectedPubKey, payload.get("pubKey").binaryValue());
        assertArrayEquals(expectedPubKey, payload.get("pubKeyId").binaryValue());
        assertEquals(1581683876, payload.get("validNotAfter").asInt());
        assertEquals(1550925476, payload.get("validNotBefore").asInt());

        logger.debug("protocol message: " + new ObjectMapper().writeValueAsString(pm));
    }

    @Test
    void testDecodeMessageECDSAv2() throws IOException, NoSuchAlgorithmException {
        byte[] message = getBinaryFixture("msgpack/v2.0-ecdsa-message.mpack");

        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        ProtocolMessage pm = decoder.decode(message);

        assertEquals(2, pm.version >> 4, "unexpected protocol version for v2 message");
        assertEquals(SIGNED & 0x0f, pm.version & 0x0f);
        assertEquals(TEST_UUID_ECDSA_V2, pm.uuid);
        assertEquals(0x00, pm.hint);
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        JsonNode payload = pm.getPayload();
        assertArrayEquals(
            MessageDigest.getInstance("SHA-256").digest("UBIRCH".getBytes()),
            Base64.getDecoder().decode(payload.asText()));
    }

    @Test
    void testDecodeKeyRegistrationMessageECDSAv2() throws IOException, DecoderException {

        byte[] message = getBinaryFixture("msgpack/v2.0-ecdsa-register.mpack");

        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        ProtocolMessage pm = decoder.decode(message);

        assertEquals(2, pm.version >> 4, "unexpected protocol version for v2 message");
        assertEquals(SIGNED & 0x0f, pm.version & 0x0f);
        assertEquals(TEST_UUID_ECDSA_V2, pm.uuid);
        assertEquals(0x01, pm.hint);
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        JsonNode payload = pm.getPayload();
        byte[] expectedPubKey = Hex.decodeHex("a3c14cff55de8459fe4367a98cc399c19bb74615e24b4254742ff0393d71bd8dd55af363480e2ff201d5dca2603cbd9cd68ffea783cec86ff50aabbc540fc75d".toCharArray());
        assertEquals("ECDSHA_SHA_256", payload.get("algorithm").asText());
        assertEquals(1550925476, payload.get("created").asInt());
        assertEquals(16, payload.get("hwDeviceId").binaryValue().length);
        assertArrayEquals(UUIDUtil.uuidToBytes(TEST_UUID_ECDSA_V2), payload.get("hwDeviceId").binaryValue());
        assertArrayEquals(expectedPubKey, payload.get("pubKey").binaryValue());
        assertArrayEquals(expectedPubKey, payload.get("pubKeyId").binaryValue());
        assertEquals(1581683876, payload.get("validNotAfter").asInt());
        assertEquals(1550925476, payload.get("validNotBefore").asInt());

        logger.debug("protocol message: " + new ObjectMapper().writeValueAsString(pm));
    }
}
