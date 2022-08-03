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

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the implementations of {@link MsgPackProtocolDecoder}.
 *
 * @author Matthias L. Jugel
 */
class MsgPackProtocolDecoderTest extends ProtocolFixtures {

    private static final byte[] expectedSimpleSignature =
            Arrays.copyOfRange(expectedSignedMessage, expectedSignedMessage.length - 64, expectedSignedMessage.length);

    @Test
    void testInstance() {
        ProtocolDecoder<byte[]> decoder = MsgPackProtocolDecoder.getDecoder();
        assertNotNull(decoder, "decoder should not be null");
        assertEquals(decoder, MsgPackProtocolDecoder.getDecoder(), "decoder should be a singleton");
    }

    @Test
    void testBrokenMsgPack() {
        assertThrows(ProtocolException.class, () ->
                MsgPackProtocolDecoder.getDecoder().decode(new byte[]{(byte) 0xEF, 44}));
    }

    @Test
    void testSignedMessage() throws ProtocolException {
        ProtocolMessage pm = MsgPackProtocolDecoder.getDecoder().decode(expectedSignedMessage);
        assertEquals(ProtocolMessage.SIGNED, pm.getVersion());
        assertEquals(testUUID, pm.getUUID());
        assertNull(pm.getChain());
        assertEquals(0xEF, pm.getHint());
        assertEquals(1, pm.getPayload().asInt());
        assertArrayEquals(expectedSimpleSignature, pm.getSignature());
    }

    @Test
    void testSignedMessageFromParts() throws ProtocolException {
        ProtocolMessage pm = MsgPackProtocolDecoder.getDecoder().decode(expectedSignedMessage);
        assertEquals(ProtocolMessage.SIGNED, pm.getVersion());
        assertArrayEquals(expectedSimpleSignature, pm.getSignature());
        byte[][] dataToVerifyAndSignature = MsgPackProtocolDecoder.getDecoder().getDataToVerifyAndSignature(expectedSignedMessage);
        assertArrayEquals(pm.getSigned(), dataToVerifyAndSignature[0]);
        assertArrayEquals(pm.getSignature(), dataToVerifyAndSignature[1]);
    }

    @Test
    void testDecodeHashedTrackleMsgPack() throws ProtocolException {
        ProtocolMessage pm = MsgPackProtocolDecoder.getDecoder().decode(hashedTrackleMessage);
        assertEquals(ProtocolMessage.CHAINED, pm.getVersion());
        assertArrayEquals(expectedTrackleSignature, pm.getSignature());
        byte[][] dataToVerifyAndSignature = MsgPackProtocolDecoder.getDecoder().getDataToVerifyAndSignature(hashedTrackleMessage);
        assertArrayEquals(pm.getSigned(), dataToVerifyAndSignature[0]);
        assertArrayEquals(pm.getSignature(), dataToVerifyAndSignature[1]);
        assertArrayEquals(pm.getSigned(), expectedTrackleSigned);
    }

    @Test
    void testIsHashedTrackleTypePack() {
        assert (MsgPackProtocolDecoder.getDecoder().isHashedTrackleMsgType(hashedTrackleMessage));
    }

    @Test
    void testIsNotHashedTrackleTypePack() {
        assert (!MsgPackProtocolDecoder.getDecoder().isHashedTrackleMsgType(expectedSignedMessage));
    }

    @Test
    void testIsHashedTrackleMsgTypeSafe() throws ProtocolException {
        assert (MsgPackProtocolDecoder.getDecoder().isHashedTrackleMsgTypeSafe(hashedTrackleMessage));
    }

    @Test
    void testIsNotHashedTrackleMsgTypeSafe() throws ProtocolException {
        assert (!MsgPackProtocolDecoder.getDecoder().isHashedTrackleMsgTypeSafe(expectedSignedMessage));
    }

    @Test
    void testChainedMessage() throws ProtocolException {
        byte[] lastSignature = new byte[64];
        for (int i = 0; i < 3; i++) {
            byte[] expectedMsg = expectedChainedMessages.get(i);
            ProtocolMessage pm = MsgPackProtocolDecoder.getDecoder().decode(expectedMsg);
            assertEquals(ProtocolMessage.CHAINED, pm.getVersion());
            assertEquals(testUUID, pm.getUUID());
            assertArrayEquals(lastSignature, pm.getChain());
            assertEquals(0xEE, pm.getHint());
            assertEquals(i + 1, pm.getPayload().asInt());
            byte[] expectedSig = Arrays.copyOfRange(expectedMsg, expectedMsg.length - 64, expectedMsg.length);
            assertArrayEquals(expectedSig, pm.getSignature());
            lastSignature = expectedSig;
        }
    }

    @Test
    void testChainedMessageFromParts() throws ProtocolException {
        for (int i = 0; i < 3; i++) {
            byte[] expectedMsg = expectedChainedMessages.get(i);
            ProtocolMessage pm = MsgPackProtocolDecoder.getDecoder().decode(expectedMsg);
            assertEquals(ProtocolMessage.CHAINED, pm.getVersion());
            byte[] expectedSig = Arrays.copyOfRange(expectedMsg, expectedMsg.length - 64, expectedMsg.length);
            assertArrayEquals(expectedSig, pm.getSignature());
            byte[][] dataToVerifyAndSignature = MsgPackProtocolDecoder.getDecoder().getDataToVerifyAndSignature(expectedMsg);
            assertArrayEquals(pm.getSigned(), dataToVerifyAndSignature[0]);
            assertArrayEquals(pm.getSignature(), dataToVerifyAndSignature[1]);
        }
    }

    @Test
    void testVerifySignedMessage() throws SignatureException, ProtocolException {
        ProtocolMessage pm = MsgPackProtocolDecoder.getDecoder()
                .decode(expectedSignedMessage, (uuid, data, offset, len, signature) -> true);

        assertNotNull(pm, "protocol message must not be null");

        assertEquals(ProtocolMessage.SIGNED, pm.getVersion());
        assertEquals(testUUID, pm.getUUID());
        assertNull(pm.getChain());
        assertEquals(0xEF, pm.getHint());
        assertEquals(1, pm.getPayload().asInt());
        assertArrayEquals(expectedSimpleSignature, pm.getSignature());
    }

    @Test
    void testVerifySignedMessageFails() {
        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        assertThrows(SignatureException.class, () ->
                decoder.decode(expectedSignedMessage, (uuid, data, offset, len, signature) -> false));
    }

    @Test
    void testVerifySignedInvalidKey() {
        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        assertThrows(ProtocolException.class, () ->
                decoder.decode(expectedSignedMessage, (uuid, data, offset, len, signature) -> {
                    throw new InvalidKeyException();
                }));
    }

    @Test
    void testVerifyMsgPackEnvelopeBroken() {
        // create a broken json node and set the payload to force a JsonProcessingException
        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        assertThrows(ProtocolException.class, () ->
                decoder.decode(new byte[]{(byte) 0x91, 0x01}, (uuid, data, offset, len, signature) -> true));
    }

}
