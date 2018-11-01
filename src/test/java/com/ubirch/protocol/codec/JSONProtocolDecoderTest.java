/*
 * Copyright (c) 2018 ubirch GmbH
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
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the implementations of {@link JSONProtocolDecoder}.
 *
 * @author Matthias L. Jugel
 */
class JSONProtocolDecoderTest extends ProtocolFixtures {
	private final static byte[] expectedSimpleSignature = Base64.getDecoder().decode(
					"YyC6ChlzkEOxL0oH98ytZz4ZOUEmE3uFlt3Ildy2X1/Pdp9BtSQvMScZKjUK6Y0berKHKR7LRYAwD7Ko+BBXCA==");

	@Test
	void testJSONProtocolDecoderInstance() {
		ProtocolDecoder<String> decoder = JSONProtocolDecoder.getDecoder();
		assertNotNull(decoder, "decoder should not be null");
		assertEquals(decoder, JSONProtocolDecoder.getDecoder(), "decoder should be a singleton");
	}

	@Test
	void testJSONProtocolDecoderBrokenJson() {
		assertThrows(ProtocolException.class, () -> JSONProtocolDecoder.getDecoder().decode("{"));
	}

	@Test
	void testJSONProtocolDecoderSignedMessage() throws ProtocolException {
		ProtocolMessage pm = JSONProtocolDecoder.getDecoder().decode(expectedSignedMessageJson);
		assertEquals(ProtocolMessage.SIGNED, pm.getVersion());
		assertEquals(testUUID, pm.getUUID());
		assertNull(pm.getChain());
		assertEquals(0xEF, pm.getHint());
		assertEquals(1, pm.getPayload().asInt());
		assertArrayEquals(expectedSimpleSignature, pm.getSignature());
	}

	@Test
	void testJSONProtocolDecoderChainedMessage() throws ProtocolException {
		ProtocolMessage pm = JSONProtocolDecoder.getDecoder().decode(expectedChainedMessagesJson.get(0));
		assertEquals(ProtocolMessage.CHAINED, pm.getVersion());
		assertEquals(testUUID, pm.getUUID());
		assertArrayEquals(new byte[64], pm.getChain());
		assertEquals(0xEE, pm.getHint());
		assertEquals(1, pm.getPayload().asInt());
		assertArrayEquals(expectedSimpleSignature, pm.getSignature());
	}

	@Test
	void testJSONProtocolDecoderVerifySignedMessage() throws SignatureException, ProtocolException {
		ProtocolMessage pm = JSONProtocolDecoder.getDecoder()
						.decode(expectedSignedMessageJson, (uuid, data, offset, len, signature) -> true);

		assertNotNull(pm, "protocol message must not be null");

		assertEquals(ProtocolMessage.SIGNED, pm.getVersion());
		assertEquals(testUUID, pm.getUUID());
		assertNull(pm.getChain());
		assertEquals(0xEF, pm.getHint());
		assertEquals(1, pm.getPayload().asInt());
		assertArrayEquals(expectedSimpleSignature, pm.getSignature());
	}

	@Test
	void testJSONProtocolDecoderVerifySignedMessageFails() {
		JSONProtocolDecoder decoder = JSONProtocolDecoder.getDecoder();
		assertThrows(SignatureException.class, () ->
						decoder.decode(expectedSignedMessageJson, (uuid, data, offset, len, signature) -> false));
	}

	@Test
	void testJSONProtocolDecoderVerifySignedInvalidKey() {
		JSONProtocolDecoder decoder = JSONProtocolDecoder.getDecoder();
		assertThrows(ProtocolException.class, () ->
						decoder.decode(expectedSignedMessageJson, (uuid, data, offset, len, signature) -> {
							throw new InvalidKeyException();
						}));
	}

	@Test
	void testJSONProtocolDecoderVerifyJsonBroken() {
		// create a broken json node and set the payload to force a JsonProcessingException
		JSONProtocolDecoder decoder = new JSONProtocolDecoder() {
			@Override
			public ProtocolMessage decode(String message) throws ProtocolException {
				throw new ProtocolException("failed");
			}
		};
		assertThrows(ProtocolException.class, () ->
						decoder.decode(expectedSignedMessageJson, (uuid, data, offset, len, signature) -> true));
	}

	@Test
	void testJSONProtocolDecoderFails() {
		assertThrows(ProtocolException.class, () -> JSONProtocolDecoder.getDecoder().decode("X"));
	}
}