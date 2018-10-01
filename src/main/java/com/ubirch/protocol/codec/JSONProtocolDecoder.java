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
public class JSONProtocolDecoder implements ProtocolDecoder<ProtocolMessageEnvelope, String> {
	private final ObjectMapper mapper = new ObjectMapper();

	private static JSONProtocolDecoder instance = new JSONProtocolDecoder();

	public static JSONProtocolDecoder getDecoder() {
		return instance;
	}

	public ProtocolMessageEnvelope decode(String message, ProtocolVerifier verifier) throws ProtocolException, SignatureException {
		ProtocolMessageEnvelope envelope = new ProtocolMessageEnvelope(decode(message));
		try {
			byte[] bytesToVerify = mapper.writeValueAsBytes(envelope.getMessage().getPayload());
			if (!verifier.verify(envelope.getMessage().getUUID(), bytesToVerify, 0, bytesToVerify.length,
							envelope.getMessage().getSignature()))
				throw new SignatureException(String.format("signature verification failed: %s", envelope.getMessage()));
			envelope.setRaw(message.getBytes(StandardCharsets.UTF_8));
			return envelope;
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
