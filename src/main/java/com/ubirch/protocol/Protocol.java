/*
 * Copyright 2018 ubirch GmbH
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

package com.ubirch.protocol;

import com.ubirch.protocol.codec.JSONProtocolDecoder;
import com.ubirch.protocol.codec.JSONProtocolEncoder;
import com.ubirch.protocol.codec.MsgPackProtocolDecoder;
import com.ubirch.protocol.codec.MsgPackProtocolEncoder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.UUID;

/**
 * Wrapper for the ubirch-protocol.
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public abstract class Protocol implements ProtocolSigner, ProtocolVerifier {
	public enum Format {MSGPACK_V1, JSON_V1}

	abstract byte[] getLastSignature(UUID uuid);

	/**
	 * Create a new protocol instance.
	 */
	public Protocol() {
	}

	/**
	 * Create a new message from the given protocol message and sign it.
	 * A side effect of this procedure is an update of the fields of the protocol message parameter.
	 *
	 * @param pm     the protocol message to encode and sign
	 * @param format the target format to encode to
	 * @return the bytes representing the raw value of the message
	 * @throws ProtocolException  if the message could not be encoded
	 * @throws SignatureException if the message signing failed
	 */
	public byte[] encodeSign(ProtocolMessageEnvelope pm, Format format) throws IOException, SignatureException {
		if(pm.message.getVersion() == ProtocolMessage.CHAINED) {
			pm.getMessage().chain = getLastSignature(pm.getMessage().uuid);
		}

		switch (format) {
			case MSGPACK_V1:
				return MsgPackProtocolEncoder.getEncoder().encode(pm, this);
			case JSON_V1:
				return JSONProtocolEncoder.getEncoder().encode(pm, this).getBytes(StandardCharsets.UTF_8);
			default:
				throw new ProtocolException(String.format("unsupported target format: %s", format));
		}
	}

	/**
	 * Verify and construct a protocol message from the given byte input.
	 *
	 * @param message the binary message to decode
	 * @param format  the source fromat to decode from
	 * @return the decoded and verified protocol message
	 * @throws ProtocolException   if the decoding fails
	 * @throws SignatureException  if the signature verification fails
	 */
	public ProtocolMessageEnvelope decodeVerify(byte[] message, Format format) throws IOException, SignatureException {

		switch (format) {
			case MSGPACK_V1:
				return MsgPackProtocolDecoder.getDecoder().decode(message, this);
			case JSON_V1:
				return JSONProtocolDecoder.getDecoder().decode(new String(message, StandardCharsets.UTF_8), this);
			default:
				throw new ProtocolException(String.format("unsupported source format: %s", format));
		}


	}

	public ProtocolMessageEnvelope decodeVerify(byte[] message) throws IOException, SignatureException {
		return decodeVerify(message, Format.MSGPACK_V1);
	}
}
