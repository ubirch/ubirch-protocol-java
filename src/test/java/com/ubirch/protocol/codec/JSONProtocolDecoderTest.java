package com.ubirch.protocol.codec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolFixtures;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolMessageEnvelope;
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
		ProtocolDecoder<ProtocolMessageEnvelope, String> decoder = JSONProtocolDecoder.getDecoder();
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
		ProtocolMessageEnvelope envelope = JSONProtocolDecoder.getDecoder()
						.decode(expectedSignedMessageJson, (uuid, data, offset, len, signature) -> true);

		ProtocolMessage pm = envelope.getMessage();
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
			public ProtocolMessage decode(String message) {
				ObjectMapper mapper = new ObjectMapper();
				ObjectNode node = mapper.createObjectNode();
				node.set(null, null);
				ProtocolMessage pm = new ProtocolMessage(0, testUUID, 0, 1);
				pm.setPayload(node);
				return pm;
			}
		};
		assertThrows(ProtocolException.class, () ->
						decoder.decode(expectedSignedMessageJson, (uuid, data, offset, len, signature) -> true));
	}

}