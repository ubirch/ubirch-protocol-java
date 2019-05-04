/*
 * Copyright (c) 2019 ubirch GmbH
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
public class MsgPackProtocolEncoder extends ProtocolEncoder<byte[]> {
    private static MessagePack.PackerConfig config = new MessagePack.PackerConfig().withStr8FormatSupport(false);
    private static MsgPackProtocolEncoder instance = new MsgPackProtocolEncoder();

    public static MsgPackProtocolEncoder getEncoder() {
        return instance;
    }

    /**
     * Encodes this protocol message into the msgpack format. Modifies the given ProtocolMessage, filling
     * in the signature and encoded bytes.
     *
     * @param pm     the protocol message to encode and sign
     * @param signer the protocol signer
     * @return the msgpack encoded message as bytes
     * \
     */
    @Override
    public byte[] encode(ProtocolMessage pm, ProtocolSigner signer) throws ProtocolException, SignatureException {
        if (pm == null || signer == null) {
            throw new IllegalArgumentException("message or signer null");
        }

        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(255);
            MessagePacker packer = config.newPacker(out);

            packer.packArrayHeader(5 + (pm.getVersion() & 0x0f) - 2);
            packer.packInt(pm.getVersion());
            packer.packBinaryHeader(16).addPayload(UUIDUtil.uuidToBytes(pm.getUUID()));
            switch (pm.getVersion()) {
                case ProtocolMessage.CHAINED:
                    packer.packBinaryHeader(64);
                    byte[] chainSignature = pm.getChain();
                    if (chainSignature == null) {
                        packer.addPayload(new byte[64]);
                    } else {
                        packer.addPayload(chainSignature);
                    }
                    break;
                case ProtocolMessage.SIGNED:
                    break;
                default:
                    throw new ProtocolException(String.format("unknown protocol version: 0x%x", pm.getVersion()));
            }
            packer.packInt(pm.getHint());
            packer.flush(); // make sure everything is in the byte buffer

            // write the payload
            ObjectMapper mapper = new ObjectMapper(new MessagePackFactory());
            mapper.writeValue(out, pm.getPayload());
            packer.close(); // also closes out

            // sign the message
            byte[] dataToSign = out.toByteArray();
            byte[] signature = signer.sign(pm.getUUID(), dataToSign, 0, dataToSign.length);
            pm.setSigned(dataToSign);
            pm.setSignature(signature);

            return encode(pm);
        } catch (InvalidKeyException e) {
            throw new ProtocolException("invalid key", e);
        } catch (IOException e) {
            throw new ProtocolException("msgpack encoding failed", e);
        } catch (NullPointerException e) {
            throw new ProtocolException("msgpack encoding failed: field null?", e);
        }
    }

    public byte[] encode(ProtocolMessage pm) throws ProtocolException {
        checkProtocolMessage(pm);

        ByteArrayOutputStream out = new ByteArrayOutputStream(255);
        MessagePacker packer = config.newPacker(out);

        try {
            packer.writePayload(pm.getSigned());
            if (pm.getVersion() == 1) {
                packer.packRawStringHeader(pm.getSignature().length);
            } else {
                packer.packBinaryHeader(pm.getSignature().length);
            }
            packer.writePayload(pm.getSignature());

            packer.flush();
            packer.close();
        } catch (IOException e) {
            throw new ProtocolException("msgpack encoding failed", e);
        }

        return out.toByteArray();
    }
}
