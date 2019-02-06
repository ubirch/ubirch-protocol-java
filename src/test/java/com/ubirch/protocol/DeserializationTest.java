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
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import static com.ubirch.protocol.ProtocolMessage.CHAINED;
import static com.ubirch.protocol.ProtocolMessage.SIGNED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Add description.
 *
 * @author Matthias L. Jugel
 */

class DeserializationTest extends ProtocolFixtures {
    private final Logger logger = LoggerFactory.getLogger(DeserializationTest.class);

    @Test
    void testDecodeTrackleMessage() throws IOException {
        byte[] message = getBinaryFixture("msgpack/v0.4-trackle-production.mpack");

        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        ProtocolMessage pm = decoder.decode(message);

        assertEquals(1, pm.version >> 4, "unexpected protocol version for trackle message");
        assertEquals(CHAINED & 0x0f, pm.version & 0x0f);
        assertEquals(UUID.fromString("af931b05-acca-758b-c2aa-eb98d6f93329"), pm.uuid);
        assertEquals(0x54, pm.hint);
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        logger.debug(pm.getPayload().toString());
        ObjectMapper mapper = new ObjectMapper();

        JsonNode payload = pm.getPayload();
        assertEquals("v1.0.2-PROD-20180326103205 (v5.6.6)", payload.get(0).asText());
        assertEquals(2766, payload.get(1).asInt());
        assertEquals(3, payload.get(2).asInt());

        // the original data contains a map of timestamp:temperature, so we need to map this type accordingly
        Map<Integer, Integer> values = mapper.convertValue(payload.get(3), new TypeReference<Map<Integer, Integer>>() {
        });
        // the actual data contains one duplicated timestamp (it contains 737 data points)
        assertEquals(736, values.size());
        assertEquals(3519, (int) values.get(1533846771));
        assertEquals(3914, (int) values.get(1537214378));
    }

    @Test
    void testDecodeKeyRegistrationMessage() throws IOException {

        byte[] message = getBinaryFixture("msgpack/v1.0-register.mpack");

        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        ProtocolMessage pm = decoder.decode(message);

        assertEquals(1, pm.version >> 4, "unexpected protocol version for trackle message");
        assertEquals(SIGNED & 0x0f, pm.version & 0x0f);
        assertEquals(UUID.fromString("00000000-0000-0000-0000-000000000000"), pm.uuid);
        assertEquals(0x01, pm.hint);
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        logger.debug(pm.getPayload().toString());
        JsonNode payload = pm.getPayload();

//        byte[] expectedPubKey = new byte[64];
//        assertEquals("ECC_ED25519", payload.get("algorithm").asText());
//        assertEquals( 1542793437, payload.get("created").asInt());
//        assertEquals(16, payload.get("hwDeviceId").asText().length());
//        assertArrayEquals(new byte[16], payload.get("hwDeviceId").asText().getBytes());
//        assertArrayEquals(expectedPubKey, payload.get("pubKey").asText().getBytes());
//        assertArrayEquals(expectedPubKey, payload.get("pubKeyId").asText().getBytes());
//        assertEquals( 1574329437, payload.get("validNotAfter").asInt());
//        assertEquals( 1542793437, payload.get("validNotBefore").asInt());
    }

    public static class KeyRegistrationPayload {
        protected String algorithm;
        protected long created;
        protected byte[] hwDeviceId;
        protected byte[] pubKey;
        protected byte[] pubKeyId;
        protected long validNotAfter;
        protected long validNotBefore;
    }

}
