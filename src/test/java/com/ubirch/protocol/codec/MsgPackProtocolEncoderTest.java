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

import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolFixtures;
import com.ubirch.protocol.ProtocolMessage;
import org.junit.jupiter.api.Test;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the implementations of {@link com.ubirch.protocol.codec.MsgPackProtocolEncoder}.
 *
 * @author Matthias L. Jugel
 */
class MsgPackProtocolEncoderTest extends ProtocolFixtures {
    @Test
    void testMsgPackProtocolEncoderInstance() {
        ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();
        assertNotNull(encoder, "encoder should not be null");
        assertEquals(encoder, MsgPackProtocolEncoder.getEncoder(), "encoder should be a singleton");
    }

    @Test
    void testMsgPackProtocolEncoderEmptyEnvelopeException() {
        ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();
        ProtocolMessage pm = new ProtocolMessage();
        assertThrows(ProtocolException.class, () -> encoder.encode(pm, (uuid, data, offset, len) -> null));
    }

    @Test
    void testMsgPackProtocolEncoderVersionException() {
        ProtocolMessage pm = new ProtocolMessage(0, testUUID, 0xEF, 1);
        ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();
        assertThrows(ProtocolException.class, () -> encoder.encode(pm, (uuid, data, offset, len) -> null));
    }

    @Test
    void testMsgPackProtocolEncoderArgumentExceptions() {
        ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.SIGNED, testUUID, 0xEF, 1);
        ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();

        // check argument exceptions
        assertThrows(IllegalArgumentException.class, () -> encoder.encode(pm, null));
        assertThrows(IllegalArgumentException.class, () -> encoder.encode(null, (uuid, data, offset, len) -> null));
        assertThrows(IllegalArgumentException.class, () -> encoder.encode(null, null));
    }

    @Test
    void testMsgPackProtocolEncoderEncodeSigned() throws NoSuchAlgorithmException, SignatureException, IOException {
        ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.SIGNED, testUUID, 0xEF, 1);
        ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();

        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] msg = encoder.encode(pm, (uuid, data, offset, len) -> {
            digest.update(data, offset, len);
            return digest.digest();
        });

        byte[] expectedMessage = Arrays.copyOfRange(expectedSignedMessage, 0, expectedSignedMessage.length - 67);
        byte[] actualMessage = Arrays.copyOfRange(msg, 0, msg.length - 67);
        assertArrayEquals(expectedMessage, actualMessage);

        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(msg);
        assertEquals(5, unpacker.unpackArrayHeader());
        assertEquals(ProtocolMessage.SIGNED, unpacker.unpackInt());
        assertArrayEquals(UUIDUtil.uuidToBytes(testUUID), unpacker.readPayload(unpacker.unpackBinaryHeader()));
        assertEquals(0xEF, unpacker.unpackInt());
        assertEquals(1, unpacker.unpackInt());
        // check the SHA-512 digest of the message (fake signature)
        assertArrayEquals(expectedSignedMessageHash, unpacker.readPayload(unpacker.unpackBinaryHeader()));
    }

    @Test
    void testMsgPackProtocolEncoderEncodeChained() throws NoSuchAlgorithmException, SignatureException, IOException {
        byte[] lastSignature = new byte[64];
        for (int i = 0; i < 3; i++) {
            for (int n = 0; n < lastSignature.length; n++) {
                lastSignature[n] = (byte) i;
            }
            ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.CHAINED, testUUID, lastSignature, 0xEE, i + 1);
            ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();

            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] msg = encoder.encode(pm, (uuid, data, offset, len) -> {
                digest.update(data, offset, len);
                return digest.digest();
            });

            byte[] expectedMessage = Arrays.copyOfRange(
                    expectedChainedMessages.get(i), 0,
                    expectedChainedMessages.get(i).length - 64);
            for (int n = 0; n < lastSignature.length; n++) {
                expectedMessage[22 + n] = (byte) i;
            }

            byte[] actualMessage = Arrays.copyOfRange(msg, 0, msg.length - 64);
            assertArrayEquals(expectedMessage, actualMessage);

            MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(msg);
            assertEquals(6, unpacker.unpackArrayHeader());
            assertEquals(ProtocolMessage.CHAINED, unpacker.unpackInt());
            assertArrayEquals(UUIDUtil.uuidToBytes(testUUID), unpacker.readPayload(unpacker.unpackBinaryHeader()));
            assertArrayEquals(lastSignature, unpacker.readPayload(unpacker.unpackBinaryHeader()));
            assertEquals(0xEE, unpacker.unpackInt());
            assertEquals(i + 1, unpacker.unpackInt());

            lastSignature = pm.getSignature();
        }
    }

    @Test
    void testMsgPackProtocolEncoderInvalidKeyException() {
        ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.SIGNED, testUUID, 2, 3);

        ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();

        assertThrows(ProtocolException.class, () -> encoder.encode(pm, (uuid, data, offset, len) -> {
            throw new InvalidKeyException("test exception");
        }));
    }

    @Test
    void testMsgPackProtocolEncoderMissingSignature() {
        ProtocolMessage pm = new ProtocolMessage();

        ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();

        Exception e = assertThrows(ProtocolException.class, () -> encoder.encode(pm));
        assertEquals("missing signature", e.getMessage());
    }

    @Test
    void testMsgPackProtocolEncoderMissingSigned() {
        ProtocolMessage pm = new ProtocolMessage();
        pm.setSignature(new byte[64]);

        ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();

        Exception e = assertThrows(ProtocolException.class, () -> encoder.encode(pm));
        assertEquals("missing signed data", e.getMessage());
    }

    @Test
    void testMsgPackProtocolEncoderRecreate() throws ProtocolException {
        ProtocolMessage pm = MsgPackProtocolDecoder.getDecoder().decode(expectedSignedMessage);

        ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();

        assertArrayEquals(expectedSignedMessage, encoder.encode(pm));
    }

    @Test
    void testJSONProtocolEncoderRecreateFailsVersion() throws ProtocolException {
        ProtocolMessage pm = MsgPackProtocolDecoder.getDecoder().decode(expectedSignedMessage);
        pm.setVersion(0xFF);

        ProtocolEncoder<byte[]> encoder = MsgPackProtocolEncoder.getEncoder();

        Exception e = assertThrows(ProtocolException.class, () -> encoder.encode(pm));
        assertEquals("unknown protocol version: 0xff", e.getMessage());
    }
}