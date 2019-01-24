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

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.util.*;

/**
 * Add description.
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public class ProtocolFixtures {
    protected static UUID testUUID;
    // expected results fixtures (binary encoded)
    protected static byte[] expectedSignedMessage;
    protected static byte[] expectedSignedMessageHash;
    protected static String expectedSignedMessageJson;
    protected static byte[] expectedSignedMessageJsonHash;
    protected static String expectedSignedMessageJsonWithData;
    protected static List<byte[]> expectedChainedMessages;
    protected static List<byte[]> expectedChainedMessagesHash;
    protected static List<String> expectedChainedMessagesJson;
    // fixtures used in the test
    private static byte[] EdDSAKeyPrivatePart;
    private static byte[] EdDSAKeyPublicPart;

    @BeforeAll
    protected static void initialize() throws DecoderException, IOException {
        Properties fixtures = new Properties();
        fixtures.load(ProtocolTest.class.getResourceAsStream("/protocol_test.properties"));
        testUUID = UUID.fromString(fixtures.getProperty("uuid"));
        EdDSAKeyPrivatePart = Hex.decodeHex(fixtures.getProperty("privateKey").toCharArray());
        EdDSAKeyPublicPart = Hex.decodeHex(fixtures.getProperty("publicKey").toCharArray());

        expectedSignedMessage = Hex.decodeHex(fixtures.getProperty("signedMessage").toCharArray());
        expectedSignedMessageHash = Hex.decodeHex(fixtures.getProperty("signedMessageHash").toCharArray());

        expectedChainedMessages = new ArrayList<>(3);
        expectedChainedMessages.add(Hex.decodeHex(fixtures.getProperty("chainMessage01").toCharArray()));
        expectedChainedMessages.add(Hex.decodeHex(fixtures.getProperty("chainMessage02").toCharArray()));
        expectedChainedMessages.add(Hex.decodeHex(fixtures.getProperty("chainMessage03").toCharArray()));
        expectedChainedMessagesHash = new ArrayList<>(3);
        expectedChainedMessagesHash.add(Hex.decodeHex(fixtures.getProperty("chainMessage01Hash").toCharArray()));
        expectedChainedMessagesHash.add(Hex.decodeHex(fixtures.getProperty("chainMessage02Hash").toCharArray()));
        expectedChainedMessagesHash.add(Hex.decodeHex(fixtures.getProperty("chainMessage03Hash").toCharArray()));

        expectedSignedMessageJson = fixtures.getProperty("signedMessage.json");
        expectedSignedMessageJsonHash = Hex.decodeHex(fixtures.getProperty("signedMessageHash.json").toCharArray());
        expectedSignedMessageJsonWithData = fixtures.getProperty("signedMessageWithData.json");

        expectedChainedMessagesJson = new ArrayList<>(3);
        expectedChainedMessagesJson.add(fixtures.getProperty("chainMessage01.json"));
        expectedChainedMessagesJson.add(fixtures.getProperty("chaindMessage02.json"));
        expectedChainedMessagesJson.add(fixtures.getProperty("chainMessage03.json"));
    }

    protected byte[] getBinaryFixture(String name) throws IOException {
        InputStream in = getClass().getResourceAsStream("/" + name);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] buffer = new byte[10 * 1024];
        int len;
        while ((len = in.read(buffer)) > -1) {
            out.write(buffer, 0, len);
        }
        in.close();
        out.close();
        return out.toByteArray();
    }

    protected class TestProtocol extends Protocol {
        final byte[] zeroSignature = new byte[64];
        private final Logger logger = LoggerFactory.getLogger(TestProtocol.class);
        private KeyPair keypair;
        private EdDSAEngine signEngine;
        private MessageDigest sha512;
        private Map<UUID, byte[]> signatures = new HashMap<>();

        TestProtocol() throws NoSuchAlgorithmException {
            super();
            EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
            EdDSAPublicKey publicKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(EdDSAKeyPublicPart, spec));
            EdDSAPrivateKey privateKey = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(EdDSAKeyPrivatePart, spec));
            keypair = new KeyPair(publicKey, privateKey);
            sha512 = MessageDigest.getInstance("SHA-512");
            // Yes, we use a separate message digest instance for the sign engine! It is safer this way.
            signEngine = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
        }

        @Override
        public byte[] sign(UUID uuid, byte[] data, int offset, int len) throws InvalidKeyException, SignatureException {
            try {
                MessageDigest md = (MessageDigest) sha512.clone();
                md.update(data, offset, len);
                byte[] dataToSign = md.digest();
                signEngine.initSign(keypair.getPrivate());
                signEngine.update(dataToSign, 0, dataToSign.length);
                byte[] signature = signEngine.sign();
                signatures.put(uuid, signature);

                logger.debug(String.format("HASH: (%d) %s", dataToSign.length, Hex.encodeHexString(dataToSign)));
                logger.debug(String.format("SIGN: (%d) %s", signature.length, Hex.encodeHexString(signature)));
                return signature;
            } catch (CloneNotSupportedException e) {
                e.printStackTrace();
                return null;
            }
        }

        @Override
        public boolean verify(UUID uuid, byte[] data, int offset, int len, byte[] signature)
                throws SignatureException, InvalidKeyException {
            try {
                MessageDigest md = (MessageDigest) sha512.clone();
                md.update(data, offset, len);
                byte[] dataToVerify = md.digest();

                signEngine.initVerify(keypair.getPublic());
                signEngine.update(dataToVerify, 0, dataToVerify.length);

                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("VRFY: (%d) %s", signature.length, Hex.encodeHexString(signature)));
                }

                return signEngine.verify(signature);
            } catch (CloneNotSupportedException e) {
                e.printStackTrace();
                return false;
            }
        }

        @Override
        byte[] getLastSignature(UUID uuid) {
            return signatures.getOrDefault(uuid, zeroSignature);
        }
    }
}
