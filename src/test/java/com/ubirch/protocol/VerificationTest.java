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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ubirch.crypto.GeneratorKeyFactory;
import com.ubirch.crypto.PubKey;
import com.ubirch.crypto.utils.Curve;
import com.ubirch.protocol.codec.MsgPackProtocolDecoder;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.UUID;

import static com.ubirch.protocol.ProtocolMessage.SIGNED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test deserialization of encoded messages already in production.
 *
 * @author Matthias L. Jugel
 */

class VerificationTest extends ProtocolFixtures {
    private final Logger logger = LoggerFactory.getLogger(VerificationTest.class);

    private static final UUID TEST_UUID = UUID.fromString("ffff160c-6117-5b89-ac98-15aeb52655e0");

    @Test
    void testDecodeVerifyMessageECDSAv2() throws IOException, DecoderException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        byte[] message = getBinaryFixture("msgpack/v2.0-ecdsa-message-1.mpack");
        PubKey vk = GeneratorKeyFactory.getPrivKey(Hex.decodeHex("ce9d2d4c19d9bd988ec6fb4e77b19dc7e43bd232372e8571e71813c9dca53093"), Curve.PRIME256V1);

        ProtocolVerifier verifier = new Protocol() {
            @Override
            protected byte[] getLastSignature(UUID uuid) {
                return new byte[0];
            }

            @Override
            public byte[] sign(UUID uuid, byte[] data, int offset, int len) {
                return new byte[0];
            }

            @Override
            public boolean verify(UUID uuid, byte[] data, int offset, int len, byte[] signature) throws SignatureException, InvalidKeyException {
                try {
                    byte[] dataToVerify = new byte[len];
                    System.arraycopy(message, offset, dataToVerify, 0, len);

                    return vk.verify(dataToVerify, signature);
                } catch (NoSuchAlgorithmException e) {
                    throw new InvalidKeyException(e);
                } catch (IOException e) {
                    throw new SignatureException(e);
                }
            }
        };

        MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
        ProtocolMessage pm = decoder.decode(message, verifier);

        assertEquals(2, pm.version >> 4, "unexpected protocol version for v2 message");
        assertEquals(SIGNED & 0x0f, pm.version & 0x0f);
        assertEquals(TEST_UUID, pm.uuid);
        assertEquals(0x00, pm.hint);
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        logger.debug("protocol message: " + new ObjectMapper().writeValueAsString(pm));
    }
}
