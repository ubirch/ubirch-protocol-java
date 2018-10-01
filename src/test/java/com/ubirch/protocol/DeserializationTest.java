package com.ubirch.protocol;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ubirch.protocol.codec.MsgPackProtocolDecoder;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import static com.ubirch.protocol.ProtocolMessage.CHAINED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Add description.
 *
 * @author Matthias L. Jugel
 */

class DeserializationTest extends ProtocolFixtures {
	private final Logger logger = LoggerFactory.getLogger(DeserializationTest.class);

	@Test
	void testDecodeTrackleMessage() throws  IOException {
		byte[] message = getBinaryFixture("msgpack/v0.4-trackle-production.mpack");

		MsgPackProtocolDecoder decoder = MsgPackProtocolDecoder.getDecoder();
		ProtocolMessage pm = decoder.decode(message);

		assertEquals(CHAINED, pm.version);
		assertEquals(UUID.fromString("af931b05-acca-758b-c2aa-eb98d6f93329"), pm.uuid);
		assertEquals(0x54, pm.hint);
		byte[] expectedSignature = Arrays.copyOfRange(message, message.length - 64, message.length);
		assertArrayEquals(expectedSignature, pm.signature);

		logger.debug(pm.getPayload().toString());
		ObjectMapper mapper = new ObjectMapper();

		JsonNode payload = pm.getPayload();
		assertEquals("v1.0.2-PROD-20180326103205 (v5.6.6)", payload.get(0).asText());
		assertEquals(2766, payload.get(1).asInt());
		assertEquals(3, payload.get(2).asInt());

		// the original data contains a map of timestamp:temperature, so we need to map this type accordingly
		Map<Integer,Integer> values = mapper.convertValue(payload.get(3), new TypeReference<Map<Integer, Integer>>() {});
		// the actual data contains one duplicated timestamp (it contains 737 data points)
		assertEquals(736, values.size());
		assertEquals(3519, (int) values.get(1533846771));
		assertEquals(3914, (int) values.get(1537214378));
	}

}
