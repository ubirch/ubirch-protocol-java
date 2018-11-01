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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolFixtures;
import com.ubirch.protocol.ProtocolMessage;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the implementations of {@link com.ubirch.protocol.codec.JSONProtocolEncoder}.
 *
 * @author Matthias L. Jugel
 */
class JSONProtocolEncoderTest extends ProtocolFixtures {

	@Test
	void testJSONProtocolEncoderInstance() {
		ProtocolEncoder<String> encoder = JSONProtocolEncoder.getEncoder();
		assertNotNull(encoder, "encoder should not be null");
		assertEquals(encoder, JSONProtocolEncoder.getEncoder(), "encoder should be a singleton");
	}

	@Test
	void testJSONProtocolEncoderEmptyEnvelopeException() {
		JSONProtocolEncoder encoder = JSONProtocolEncoder.getEncoder();
		ProtocolMessage pm = new ProtocolMessage();
		assertThrows(ProtocolException.class, () -> encoder.encode(pm, (uuid, data, offset, len) -> null));
	}

	@Test
	void testJSONProtocolEncoderVersionException() {
		ProtocolMessage pm = new ProtocolMessage(0, testUUID, 0xEF, 1);
		JSONProtocolEncoder encoder = JSONProtocolEncoder.getEncoder();
		assertThrows(ProtocolException.class, () -> encoder.encode(pm, (uuid, data, offset, len) -> null));
	}

	@Test
	void testJSONProtocolEncoderArgumentExceptions() {
		ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.SIGNED, testUUID, 0xEF, 1);
		JSONProtocolEncoder encoder = JSONProtocolEncoder.getEncoder();

		// check argument exceptions
		assertThrows(IllegalArgumentException.class, () -> encoder.encode(pm, null));
		assertThrows(IllegalArgumentException.class, () -> encoder.encode(null, (uuid, data, offset, len) -> null));
		assertThrows(IllegalArgumentException.class, () -> encoder.encode(null, null));
	}


	@Test
	void testJSONProtocolEncoderEncode() throws NoSuchAlgorithmException, SignatureException, IOException {
		ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.SIGNED, testUUID, 0xEF, 1);
		JSONProtocolEncoder encoder = JSONProtocolEncoder.getEncoder();

		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		String msg = encoder.encode(pm, (uuid, data, offset, len) -> {
			digest.update(data, offset, len);
			return digest.digest();
		});

		JsonNode result = new ObjectMapper().readTree(msg);
		assertEquals(ProtocolMessage.SIGNED, result.get("version").asInt());
		assertEquals(testUUID.toString(), result.get("uuid").asText());
		assertEquals(0xEF, result.get("hint").asInt());
		assertEquals(1, result.get("payload").asInt());
		// check the SHA-512 digest of the message (fake signature)
		assertArrayEquals(expectedSignedMessageJsonHash, result.get("signature").binaryValue());
	}

	@Test
	void testJSONProtocolException() {
		// create a broken json node to force failure
		ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.SIGNED, testUUID, 2, 3) {
			@Override
			public JsonNode getPayload() {
				ObjectMapper mapper = new ObjectMapper();
				ObjectNode node = mapper.createObjectNode();
				node.set(null, null);
				return node;
			}
		};

		JSONProtocolEncoder encoder = JSONProtocolEncoder.getEncoder();

		assertThrows(ProtocolException.class, () -> encoder.encode(pm, (uuid, data, offset, len) -> null));
	}

	@Test
	void testJSONProtocolEncoderInvalidKeyException() {
		ProtocolMessage pm = new ProtocolMessage(ProtocolMessage.SIGNED, testUUID, 2, 3);

		JSONProtocolEncoder encoder = JSONProtocolEncoder.getEncoder();

		assertThrows(ProtocolException.class, () -> encoder.encode(pm, (uuid, data, offset, len) -> {
			throw new InvalidKeyException();
		}));
	}
}