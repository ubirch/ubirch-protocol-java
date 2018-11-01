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
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePackException;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.jackson.dataformat.MessagePackFactory;
import org.msgpack.value.ValueType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * The default msgpack ubirch protocol decoder.
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public class MsgPackProtocolDecoder extends ProtocolDecoder<byte[]> {
	// from end: offset in bytes for the signature (including msgpack marker bytes)
	public static final int SIGNATURE_OFFSET = 67;

	private static MsgPackProtocolDecoder instance = new MsgPackProtocolDecoder();

	public static MsgPackProtocolDecoder getDecoder() {
		return instance;
	}

	/**
	 * Decode a a protocol message from it's raw data.
	 *
	 * @param message the raw protocol message in msgpack format
	 * @return the decoded protocol message
	 * @throws ProtocolException if the decoding failed
	 */
	@Override
	public ProtocolMessage decode(byte[] message) throws ProtocolException {
		ByteArrayInputStream in = new ByteArrayInputStream(message);
		MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(in);

		ObjectMapper mapper = new ObjectMapper(new MessagePackFactory());
		ProtocolMessage pm = new ProtocolMessage();
		try {
			ValueType envelopeType = unpacker.getNextFormat().getValueType();
			int envelopeLength = unpacker.unpackArrayHeader();
			if (envelopeLength > 4 && envelopeLength < 7) {
				pm.setVersion(unpacker.unpackInt());
				pm.setUUID(UUIDUtil.bytesToUUID(unpacker.readPayload(unpacker.unpackRawStringHeader())));

				switch (pm.getVersion()) {
					case ProtocolMessage.CHAINED:
						pm.setChain(unpacker.readPayload(unpacker.unpackRawStringHeader()));
						pm.setPayload(mapper.readTree(message).get(4));
						break;
					case ProtocolMessage.SIGNED:
						pm.setPayload(mapper.readTree(message).get(3));
						break;
					default:
						throw new ProtocolException(String.format("unknown message version: 0x%04x", pm.getVersion()));
				}
				pm.setHint(unpacker.unpackInt());
				unpacker.skipValue();

				// finally store the signed data and signature for later verification
				pm.setSigned(Arrays.copyOfRange(message, 0, message.length - 67));
				pm.setSignature(unpacker.readPayload(unpacker.unpackRawStringHeader()));

				return pm;
			} else {
				throw new ProtocolException(String.format("unknown msgpack envelope format: %s[%d]", envelopeType.name(), envelopeLength));
			}
		} catch (MessagePackException e) {
			throw new ProtocolException("msgpack decoding failed", e);
		} catch (IOException e) {
			throw new ProtocolException(String.format("msgpack data corrupt at position %d", unpacker.getTotalReadBytes()), e);
		}
	}
}
