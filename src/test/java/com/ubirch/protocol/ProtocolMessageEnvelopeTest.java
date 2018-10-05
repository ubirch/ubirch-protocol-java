package com.ubirch.protocol;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Test the {@link ProtocolMessageEnvelope}.
 *
 * @author Matthias L. Jugel
 */
class ProtocolMessageEnvelopeTest {
	@Test
	void testEmptyProtocolMessage() {
		assertEquals("ProtocolMessage(v=0x0000,hint=0x00)", new ProtocolMessage().toString());
	}

	@Test
	void testProtocolMessageEnvelopeHasRaw() {
		byte[] expectedSimpleJson = "{\"key\":\"value\"}".getBytes(StandardCharsets.UTF_8);

		ProtocolMessage pm = new ProtocolMessage();
		ProtocolMessageEnvelope envelope = new ProtocolMessageEnvelope(pm, expectedSimpleJson);
		assertEquals("Envelope(ProtocolMessage(v=0x0000,hint=0x00),7b226b6579223a2276616c7565227d)", envelope.toString());
		assertArrayEquals(expectedSimpleJson, envelope.getRaw());
	}

	@Test
	void testProtocolMessageEnvelopeHasMessage() {
		ProtocolMessage pm =new ProtocolMessage();
		pm.setHint(0x01);

		ProtocolMessageEnvelope envelope = new ProtocolMessageEnvelope(pm);
		assertEquals("Envelope(ProtocolMessage(v=0x0000,hint=0x01))", envelope.toString());
		assertNull(envelope.getRaw());
	}
}