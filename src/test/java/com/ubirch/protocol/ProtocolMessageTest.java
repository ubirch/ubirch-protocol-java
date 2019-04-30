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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.ubirch.protocol.codec.JSONProtocolDecoder;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.msgpack.jackson.dataformat.MessagePackFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the {@link ProtocolMessage}.
 *
 * @author Matthias L. Jugel
 */
class ProtocolMessageTest extends ProtocolFixtures {

    private final String expectedProtocolMessage = "ProtocolMessage(v=0x0001,6eac4d0b-16e6-4508-8c46-22e7451ea5a1,hint=0x02,p={\"key\":\"value\"})";

    @Test
    void testEmptyProtocolMessage() {
        ProtocolMessage pm = new ProtocolMessage();
        assertEquals("ProtocolMessage(v=0x0000,hint=0x00)", pm.toString());
    }

    @Test
    void testSimpleProtocolMessage() {
        ProtocolMessage pm = new ProtocolMessage(1, testUUID, 2, 3);
        assertEquals("ProtocolMessage(v=0x0001,6eac4d0b-16e6-4508-8c46-22e7451ea5a1,hint=0x02,p=3)", pm.toString());
        assertEquals(1, pm.version);
        assertEquals(testUUID, pm.uuid);
        assertEquals(2, pm.hint);
        assertEquals(3, pm.payload.asInt());
    }

    @Test
    void testChainedProtocolMessage() {
        Random random = new Random();
        byte[] expectedChain = new byte[64];
        random.nextBytes(expectedChain);

        ProtocolMessage pm = new ProtocolMessage(1, testUUID, expectedChain, 2, 3);
        String expectedMsg = String.format(
                "ProtocolMessage(v=0x0001,6eac4d0b-16e6-4508-8c46-22e7451ea5a1,chain=%s,hint=0x02,p=3)",
                new String(Base64.encodeBase64(expectedChain), StandardCharsets.UTF_8)
        );
        assertEquals(expectedMsg, pm.toString());

        assertEquals(1, pm.version);
        assertEquals(testUUID, pm.uuid);
        assertArrayEquals(expectedChain, pm.chain);
        assertEquals(2, pm.hint);
        assertEquals(3, pm.payload.asInt());
    }

    @Test
    void testChainedProtocolMessageWithSignature() {
        Random random = new Random();
        byte[] expectedChain = new byte[64];
        random.nextBytes(expectedChain);
        byte[] expectedSign = new byte[64];
        random.nextBytes(expectedSign);

        ProtocolMessage pm = new ProtocolMessage(1, testUUID, expectedChain, 2, 3);
        pm.signature = expectedSign;

        String expectedMsg = String.format(
                "ProtocolMessage(v=0x0001,6eac4d0b-16e6-4508-8c46-22e7451ea5a1,chain=%s,hint=0x02,p=3,s=%s)",
                new String(Base64.encodeBase64(expectedChain), StandardCharsets.UTF_8),
                new String(Base64.encodeBase64(expectedSign), StandardCharsets.UTF_8)
        );
        assertEquals(expectedMsg, pm.toString());

        assertEquals(1, pm.version);
        assertEquals(testUUID, pm.uuid);
        assertArrayEquals(expectedChain, pm.chain);
        assertEquals(2, pm.hint);
        assertEquals(3, pm.payload.asInt());
        assertArrayEquals(expectedSign, pm.signature);
    }

    @Test
    void testCreateSimpleJsonProtocolMessage() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        String expectedSimpleJson = "{\"key\":\"value\"}";
        JsonNode expected = mapper.readTree(expectedSimpleJson);

        ProtocolMessage pm = new ProtocolMessage(1, testUUID, 2, expected);
        assertEquals(expectedProtocolMessage, pm.toString());
    }

    @Test
    void testCreateSimpleMsgPackProtocolMessage() throws IOException, DecoderException {
        ObjectMapper mapper = new ObjectMapper(new MessagePackFactory());
        JsonNode expectedSimpleJson = mapper.readTree(Hex.decodeHex("81a36b6579a576616c7565".toCharArray()));

        ProtocolMessage pm = new ProtocolMessage(1, testUUID, 2, expectedSimpleJson);
        assertEquals(expectedProtocolMessage, pm.toString());
    }

    @Test
    void testProtocolMessageInternalView() throws IOException {
        ProtocolMessage pm = JSONProtocolDecoder.getDecoder().decode(expectedSignedMessageJson);
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
        mapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
        mapper.configure(MapperFeature.DEFAULT_VIEW_INCLUSION, false);
        mapper.setConfig(mapper.getSerializationConfig().withView(ProtocolMessageViews.WithSignedData.class));

        byte[] internalSerialized = mapper.writeValueAsBytes(pm);

        assertEquals(expectedSignedMessageJsonWithData, new String(internalSerialized));
    }

    @Test
    void testProtocolMessageVerifyable() throws ProtocolException, NoSuchAlgorithmException, InvalidKeyException {
        ProtocolMessage pm = JSONProtocolDecoder.getDecoder().decode(expectedSignedMessageJson);

        TestProtocol proto = new TestProtocol();
        assertDoesNotThrow(() -> assertTrue(proto.verify(pm.getUUID(), pm.getSigned(), 0, pm.getSigned().length, pm.getSignature())));
    }

    @Test
    void testProtocolMessageWithEmptySignature() throws ProtocolException {
        ProtocolMessage pm = JSONProtocolDecoder.getDecoder().decode("{}");
        assertNull(pm.signed);
    }

}