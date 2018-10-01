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
public class JSONProtocolEncoder implements ProtocolEncoder<ProtocolMessageEnvelope, String> {
	private static JSONProtocolEncoder instance = new JSONProtocolEncoder();
	private ObjectMapper mapper = new ObjectMapper();

	public static JSONProtocolEncoder getEncoder() {
		return instance;
	}

	public JSONProtocolEncoder() {
		mapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
	}

	@Override
	public String encode(ProtocolMessageEnvelope envelope, ProtocolSigner signer) throws ProtocolException, SignatureException {
		if(envelope == null || signer == null) {
			throw new IllegalArgumentException("envelope or signer null");
		}

		ProtocolMessage pm = envelope.getMessage();
		if(pm == null) {
			throw new ProtocolException("empty mesage can't be encoded: "+envelope);
		}

		int protocolVersion = pm.getVersion();
		if(protocolVersion != ProtocolMessage.SIGNED && protocolVersion != ProtocolMessage.CHAINED) {
			throw new ProtocolException(String.format("unknown protocol version: 0x%04x", pm.getVersion()));
		}

		try {
			byte[] bytesToSign = mapper.writeValueAsBytes(pm.getPayload());
			byte[] signature = signer.sign(pm.getUUID(), bytesToSign, 0, bytesToSign.length);
			pm.setSignature(signature);
			envelope.setRaw(mapper.writeValueAsBytes(pm));
			return new String(envelope.getRaw(), StandardCharsets.UTF_8);
		} catch (JsonProcessingException e) {
			throw new ProtocolException("json encoding failed", e);
		} catch (InvalidKeyException e) {
			throw new ProtocolException("invalid key", e);
		}
	}
}
