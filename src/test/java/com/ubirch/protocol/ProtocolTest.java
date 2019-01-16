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
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;

import static com.ubirch.protocol.ProtocolMessage.CHAINED;
import static com.ubirch.protocol.ProtocolMessage.SIGNED;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the ubirch Protocol.
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public class ProtocolTest extends ProtocolFixtures {
    private final Logger logger = LoggerFactory.getLogger(ProtocolTest.class);

    @Test
    void testUnsupportedTargetFormat() {
        assertThrows(ProtocolException.class, () -> new TestProtocol().encodeSign(new ProtocolMessage(), Protocol.Format.UNSUPPORTED));
    }

    @Test
    void testUnsupportedSourceFormat() {
        assertThrows(ProtocolException.class, () -> new TestProtocol().decodeVerify("1".getBytes(), Protocol.Format.UNSUPPORTED));
    }

    @Test
    void testCreateSignedMessage() throws IOException, GeneralSecurityException {
        Protocol p = new TestProtocol();

        ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.SIGNED, testUUID, 0xEF, 1);
        byte[] message = p.encodeSign(pm, Protocol.Format.MSGPACK_V1);
        logger.debug(String.format("MESSAGE: %s", Hex.encodeHexString(message)));

        assertArrayEquals(expectedSignedMessage, message);
    }

    @Test
    void testCreateChainedMessages() throws GeneralSecurityException, IOException {
        Protocol p = new TestProtocol();

        for (int i = 0; i < 3; i++) {
            ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.CHAINED, testUUID, new byte[]{1, 2, 3}, 0xEE, i + 1);
            byte[] message = p.encodeSign(pm, Protocol.Format.MSGPACK_V1);
            logger.debug(String.format("EXPECTED: %s", Hex.encodeHexString(expectedChainedMessages.get(i))));
            logger.debug(String.format("MESSAGE : %s", Hex.encodeHexString(message)));
            assertArrayEquals(expectedChainedMessages.get(i), message, String.format("message %d failed", i + 1));
        }
    }

    @Test
    void testVerifySignedMessage() throws NoSuchAlgorithmException {
        Protocol p = new TestProtocol();

        assertDoesNotThrow(() -> {
            ProtocolMessage pm = p.decodeVerify(expectedSignedMessage);
            logger.debug(pm.toString());
            assertEquals(SIGNED, pm.version);
            assertEquals(testUUID, pm.uuid);
            assertEquals(0xEF, pm.hint);
            byte[] expectedSignature = Arrays.copyOfRange(expectedSignedMessage,
                    expectedSignedMessage.length - 64, expectedSignedMessage.length);
            assertArrayEquals(expectedSignature, pm.signature);
        });
    }

    @Test
    void testVerifySignedMessageFailsWithBrokenMessage() throws NoSuchAlgorithmException {
        Protocol p = new TestProtocol();

        for (int i = 0; i < expectedSignedMessage.length - 67; i++) {
            byte[] hackedSignedMessage = expectedSignedMessage.clone();
            hackedSignedMessage[i] ^= hackedSignedMessage[i];

            assertThrows(Exception.class, () -> p.decodeVerify(hackedSignedMessage), String.format("unexpected exception at index %d", i));
        }
    }

    @Test
    void testVerifySignedMessageFailsWithBrokenSignature() throws NoSuchAlgorithmException {
        Protocol p = new TestProtocol();

        byte[] hackedSignedMessage = expectedSignedMessage.clone();
        int signatureOffset = hackedSignedMessage.length - 64;
        hackedSignedMessage[signatureOffset + 10] ^= hackedSignedMessage[signatureOffset + 10];

        assertThrows(SignatureException.class, () -> p.decodeVerify(hackedSignedMessage));
    }

    @RepeatedTest(value = 3, name = "testVerifyChainedMessage ({currentRepetition}/{totalRepetitions})")
    void testVerifyChainedMessage(RepetitionInfo r) throws NoSuchAlgorithmException {
        Protocol p = new TestProtocol();

        assertDoesNotThrow(() -> {

            int msgNo = r.getCurrentRepetition() - 1;
            byte[] message = expectedChainedMessages.get(msgNo);
            ProtocolMessage pm = p.decodeVerify(message);
            logger.debug(pm.toString());
            assertEquals(CHAINED, pm.version);
            assertEquals(testUUID, pm.uuid);
            // check the chain signature (first is empty)
            if (msgNo == 0) {
                assertArrayEquals(new byte[64], pm.chain);
            } else {
                byte[] prev = expectedChainedMessages.get(msgNo - 1);
                byte[] expectedChainSignature = Arrays.copyOfRange(prev, prev.length - 64, prev.length);
                assertArrayEquals(expectedChainSignature, pm.chain);
            }

            assertEquals(0xEE, pm.hint);
            byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
            assertArrayEquals(expectedSignature, pm.signature);
        });
    }

    @Test
    void testCreateSignedJSONMessage() throws NoSuchAlgorithmException, IOException, SignatureException {
        Protocol p = new TestProtocol();

        ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.SIGNED, testUUID, 0xEF, 1);
        String encoded = new String(p.encodeSign(pm, Protocol.Format.JSON_V1), StandardCharsets.UTF_8);

        assertEquals(expectedSignedMessageJson, encoded);
    }

    @Test
    void testCreateChainedJSONMessages() throws GeneralSecurityException, IOException {
        Protocol p = new TestProtocol();

        for (int i = 0; i < 3; i++) {
            ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.CHAINED, testUUID, new byte[]{1, 2, 3}, 0xEE, i + 1);
            String message = new String(p.encodeSign(pm, Protocol.Format.JSON_V1), StandardCharsets.UTF_8);
            logger.debug(String.format("EXPECTED: %s", expectedChainedMessagesJson.get(i)));
            logger.debug(String.format("MESSAGE : %s", message));
            assertEquals(expectedChainedMessagesJson.get(i), message, String.format("message %d failed", i + 1));
        }
    }

    @Test
    void testVerifyJSONMessage() throws NoSuchAlgorithmException, IOException, SignatureException {
        Protocol p = new TestProtocol();
        ProtocolMessage pm = p.decodeVerify(expectedSignedMessageJson.getBytes(StandardCharsets.UTF_8), Protocol.Format.JSON_V1);
        assertEquals(SIGNED, pm.version);
        assertEquals(testUUID, pm.uuid);
        assertEquals(0xEF, pm.hint);
    }

    @RepeatedTest(value = 3, name = "testVerifyChainedMessage ({currentRepetition}/{totalRepetitions})")
    void testVerifyChainedJSONMessage(RepetitionInfo r) throws NoSuchAlgorithmException {
        Protocol p = new TestProtocol();

        assertDoesNotThrow(() -> {
            int msgNo = r.getCurrentRepetition() - 1;
            String message = expectedChainedMessagesJson.get(msgNo);
            ProtocolMessage pm = p.decodeVerify(message.getBytes(StandardCharsets.UTF_8), Protocol.Format.JSON_V1);
            logger.debug(pm.toString());
            assertEquals(CHAINED, pm.version);
            assertEquals(testUUID, pm.uuid);
            // check the chain signature (first is empty)
            if (msgNo == 0) {
                assertArrayEquals(new byte[64], pm.chain);
            } else {
                JsonNode prev = new ObjectMapper().readTree(expectedChainedMessagesJson.get(msgNo - 1));
                byte[] expectedChainSignature = prev.get("signature").binaryValue();
                assertArrayEquals(expectedChainSignature, pm.chain);
            }

            assertEquals(0xEE, pm.hint);
        });
    }

    @Test
    void testVerifyJSONtoMsgPack() throws NoSuchAlgorithmException, IOException, SignatureException {
        Protocol p = new TestProtocol();
        ProtocolMessage pm = p.decodeVerify(expectedSignedMessageJson.getBytes(StandardCharsets.UTF_8), Protocol.Format.JSON_V1);
        assertEquals(SIGNED, pm.version);
        assertEquals(testUUID, pm.uuid);
        assertEquals(0xEF, pm.hint);

        // re-encode in msgpack and expect it to match the msgpack variant
        assertArrayEquals(expectedSignedMessage, p.encodeSign(pm, Protocol.Format.MSGPACK_V1));
    }
}
