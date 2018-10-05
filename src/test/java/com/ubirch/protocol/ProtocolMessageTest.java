package com.ubirch.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.msgpack.jackson.dataformat.MessagePackFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test the {@link ProtocolMessage}.
 *
 * @author Matthias L. Jugel
 */
class ProtocolMessageTest extends ProtocolFixtures {

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

	private final String expectedProtocolMessage = "ProtocolMessage(v=0x0001,6eac4d0b-16e6-4508-8c46-22e7451ea5a1,hint=0x02,p={\"key\":\"value\"})";

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
}