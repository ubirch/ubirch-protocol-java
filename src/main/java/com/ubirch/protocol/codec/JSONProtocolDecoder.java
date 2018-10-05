package com.ubirch.protocol.codec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolMessageEnvelope;
import com.ubirch.protocol.ProtocolVerifier;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.SignatureException;

/**
 * Simple JSON protocol decoder.
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public class JSONProtocolDecoder implements ProtocolDecoder<String> {
	private final ObjectMapper mapper = new ObjectMapper();

	private static JSONProtocolDecoder instance = new JSONProtocolDecoder();

	public static JSONProtocolDecoder getDecoder() {
		return instance;
	}

	public ProtocolMessage decode(String message, ProtocolVerifier verifier) throws ProtocolException, SignatureException {
		ProtocolMessage pm = decode(message);
		try {
			byte[] bytesToVerify = mapper.writeValueAsBytes(pm.getPayload());
			if (!verifier.verify(pm.getUUID(), bytesToVerify, 0, bytesToVerify.length, pm.getSignature()))
				throw new SignatureException(String.format("signature verification failed: %s", pm));
			return pm;
		} catch (JsonProcessingException e) {
			throw new ProtocolException("json payload processing failed", e);
		} catch (InvalidKeyException e) {
			throw new ProtocolException("invalid key", e);
		}
	}

	public ProtocolMessage decode(String message) throws ProtocolException {
		try {
			return mapper.readValue(message, ProtocolMessage.class);
		} catch (IOException e) {
			throw new ProtocolException("json decoding failed", e);
		}
	}
}
