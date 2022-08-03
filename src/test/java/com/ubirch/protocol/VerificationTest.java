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
import org.bouncycastle.util.encoders.Base64;
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
import static com.ubirch.protocol.codec.ProtocolHints.BINARY_OR_UNKNOWN_PAYLOAD_MSG_PACK_HINT;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test deserialization of encoded messages already in production.
 *
 * @author Matthias L. Jugel
 */

class VerificationTest extends ProtocolFixtures {
    private final Logger logger = LoggerFactory.getLogger(VerificationTest.class);

    private static final UUID TEST_UUID = UUID.fromString("ffff160c-6117-5b89-ac98-15aeb52655e0");

    @Test
    void testDecodeVerifyMessageECDSAv2() throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        byte[] message = getBinaryFixture("msgpack/v2.0-ecdsa-message-1.mpack");
        PubKey vk = GeneratorKeyFactory.getPubKey(Base64.decode("kvdvWQ7NOT+HLDcrFqP/UZWy4QVcjfmmkfyzAgg8bitaK/FbHUPeqEji0UmCSlyPk5+4mEaEiZAHnJKOyqUZxA=="), Curve.PRIME256V1);

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
        assertEquals(BINARY_OR_UNKNOWN_PAYLOAD_MSG_PACK_HINT, pm.hint);
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        logger.debug("protocol message: " + new ObjectMapper().writeValueAsString(pm));
    }

    @Test
    void testDecodeVerifyMessageECDSAv2FromParts() throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        byte[] message = getBinaryFixture("msgpack/v2.0-ecdsa-message-1.mpack");
        PubKey vk = GeneratorKeyFactory.getPubKey(Base64.decode("kvdvWQ7NOT+HLDcrFqP/UZWy4QVcjfmmkfyzAgg8bitaK/FbHUPeqEji0UmCSlyPk5+4mEaEiZAHnJKOyqUZxA=="), Curve.PRIME256V1);

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

        byte[][] dataToVerifyAndSignature = MsgPackProtocolDecoder.getDecoder().getDataToVerifyAndSignature(message);

        byte[] dataToVerify = dataToVerifyAndSignature[0];
        byte[] signature = dataToVerifyAndSignature[1];

        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, signature);
        boolean verify = verifier.verify(UUID.randomUUID(), dataToVerify, 0, dataToVerify.length, signature);
        assertTrue(verify);

    }

    @Test
    void testDecodeVerifyMessageECDSACheck() throws InvalidKeyException, NoSuchAlgorithmException, IOException, SignatureException {
        byte[] message = Base64.decode("lSLEEP//FgxhF1uJrJgVrrUmVeAAxECUnW4kkga5FhldAMYFX7s8ZUTQwYZpV3ObvNKa27c+wVoGfmGN9zQwPbl2hXBq2femGe6NzSjUtQwAIVMXrERexEBKdNrNNjCpzGR/PwNNxxIwjFL++EEoSquEAyW/JW5cPblVnxC+rIgt4+0gUFbWy5IAZcOmmvtDFeP/u/G1lIU7");
        PubKey vk = GeneratorKeyFactory.getPubKey(Base64.decode("kvdvWQ7NOT+HLDcrFqP/UZWy4QVcjfmmkfyzAgg8bitaK/FbHUPeqEji0UmCSlyPk5+4mEaEiZAHnJKOyqUZxA=="), Curve.PRIME256V1);

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
        logger.info("DATA: " + Base64.toBase64String(pm.getSigned()));
        logger.info("SIGN: " + Base64.toBase64String(pm.getSignature()));

        assertEquals(2, pm.version >> 4, "unexpected protocol version for v2 message");
        assertEquals(SIGNED & 0x0f, pm.version & 0x0f);
        assertEquals(TEST_UUID, pm.uuid);
        assertEquals(BINARY_OR_UNKNOWN_PAYLOAD_MSG_PACK_HINT, pm.hint);
        assertArrayEquals(Base64.decode("lJ1uJJIGuRYZXQDGBV+7PGVE0MGGaVdzm7zSmtu3PsFaBn5hjfc0MD25doVwatn3phnujc0o1LUMACFTF6xEXg=="), pm.getPayload().binaryValue());
        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, pm.signature);

        logger.debug("protocol message: " + new ObjectMapper().writeValueAsString(pm));
    }

    @Test
    void testDecodeVerifyMessageECDSACheckFromParts() throws InvalidKeyException, NoSuchAlgorithmException, IOException, SignatureException {
        byte[] message = Base64.decode("lSLEEP//FgxhF1uJrJgVrrUmVeAAxECUnW4kkga5FhldAMYFX7s8ZUTQwYZpV3ObvNKa27c+wVoGfmGN9zQwPbl2hXBq2femGe6NzSjUtQwAIVMXrERexEBKdNrNNjCpzGR/PwNNxxIwjFL++EEoSquEAyW/JW5cPblVnxC+rIgt4+0gUFbWy5IAZcOmmvtDFeP/u/G1lIU7");
        PubKey vk = GeneratorKeyFactory.getPubKey(Base64.decode("kvdvWQ7NOT+HLDcrFqP/UZWy4QVcjfmmkfyzAgg8bitaK/FbHUPeqEji0UmCSlyPk5+4mEaEiZAHnJKOyqUZxA=="), Curve.PRIME256V1);

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

        byte[][] dataToVerifyAndSignature = MsgPackProtocolDecoder.getDecoder().getDataToVerifyAndSignature(message);
        byte[] dataToVerify = dataToVerifyAndSignature[0];
        byte[] signature = dataToVerifyAndSignature[1];

        byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
        assertArrayEquals(expectedSignature, signature);
        boolean verify = verifier.verify(UUID.randomUUID(), dataToVerify, 0, dataToVerify.length, signature);
        assertTrue(verify);

    }

}
