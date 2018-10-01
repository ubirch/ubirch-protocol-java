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

package com.ubirch.protocol.codec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolMessageEnvelope;
import com.ubirch.protocol.ProtocolSigner;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePacker;
import org.msgpack.jackson.dataformat.MessagePackFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.SignatureException;

/**
 * The default msgpack protocol encoder.
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public class MsgPackProtocolEncoder implements ProtocolEncoder<ProtocolMessageEnvelope, byte[]> {
	private static MessagePack.PackerConfig config = new MessagePack.PackerConfig().withStr8FormatSupport(false);
	private static MsgPackProtocolEncoder instance = new MsgPackProtocolEncoder();

	public static MsgPackProtocolEncoder getEncoder() {
		return instance;
	}

	/**
	 * Encodes this protocol message into the msgpack format. Modifies the given ProtocolMessage, filling
	 * in the signature and encoded bytes.
	 *
	 * @param envelope the protocol message to encode and sign
	 * @param signer   the protocol signer
	 * @return the msgpack encoded message as bytes
	 * \
	 */
	@Override
	public byte[] encode(ProtocolMessageEnvelope envelope, ProtocolSigner signer)
					throws ProtocolException, SignatureException {
		if (envelope == null || signer == null) {
			throw new IllegalArgumentException("envelope or signer null");
		}

		ProtocolMessage pm = envelope.getMessage();
		if (pm == null) {
			throw new ProtocolException("empty mesage can't be encoded: " + envelope);
		}

		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream(255);
			MessagePacker packer = config.newPacker(out);

			packer.packArrayHeader(5 + (pm.getVersion() & 0x0f) - 2);
			packer.packInt(pm.getVersion());
			packer.packRawStringHeader(16).addPayload(UUIDUtil.uuidToBytes(pm.getUUID()));
			switch (pm.getVersion()) {
				case ProtocolMessage.CHAINED:
					packer.packRawStringHeader(64);
					byte[] chainSignature = pm.getChain();
					if (chainSignature == null) packer.addPayload(new byte[64]);
					else packer.addPayload(chainSignature);
					break;
				case ProtocolMessage.SIGNED:
					break;
				default:
					throw new ProtocolException(String.format("unknown protocol version: 0x%04x", pm.getVersion()));
			}
			packer.packInt(pm.getHint());
			packer.flush();

			// write the payload
			ObjectMapper mapper = new ObjectMapper(new MessagePackFactory());
			mapper.writeValue(out, pm.getPayload());
			byte[] dataToSign = out.toByteArray();

			// sign the hash
			byte[] signature = signer.sign(pm.getUUID(), dataToSign, 0, dataToSign.length);
			pm.setSignature(signature);
			packer.packRawStringHeader(signature.length);
			packer.writePayload(signature);
			packer.flush();
			packer.close();

			envelope.setRaw(out.toByteArray());

			return envelope.getRaw();
		} catch (IOException e) {
			throw new ProtocolException("msgpack encoding failed", e);
		} catch (InvalidKeyException e) {
			throw new ProtocolException("invalid key", e);
		}
	}

}
