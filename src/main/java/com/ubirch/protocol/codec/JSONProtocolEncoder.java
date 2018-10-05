package com.ubirch.protocol.codec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolMessageEnvelope;
import com.ubirch.protocol.ProtocolSigner;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.SignatureException;

/**
 * Simpe JSON protocol encoder.
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public class JSONProtocolEncoder implements ProtocolEncoder<String> {
	private static JSONProtocolEncoder instance = new JSONProtocolEncoder();
	private ObjectMapper mapper = new ObjectMapper();

	public static JSONProtocolEncoder getEncoder() {
		return instance;
	}

	public JSONProtocolEncoder() {
		mapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
	}

	@Override
	public String encode(ProtocolMessage pm, ProtocolSigner signer) throws ProtocolException, SignatureException {
		if(pm == null || signer == null) {
			throw new IllegalArgumentException("message or signer null");
		}

		int protocolVersion = pm.getVersion();
		if(protocolVersion != ProtocolMessage.SIGNED && protocolVersion != ProtocolMessage.CHAINED) {
			throw new ProtocolException(String.format("unknown protocol version: 0x%04x", pm.getVersion()));
		}

		try {
			byte[] bytesToSign = mapper.writeValueAsBytes(pm.getPayload());
			byte[] signature = signer.sign(pm.getUUID(), bytesToSign, 0, bytesToSign.length);
			pm.setSignature(signature);
			return new String(mapper.writeValueAsBytes(pm), StandardCharsets.UTF_8);
		} catch (JsonProcessingException e) {
			throw new ProtocolException("json encoding failed", e);
		} catch (InvalidKeyException e) {
			throw new ProtocolException("invalid key", e);
		}
	}
}
