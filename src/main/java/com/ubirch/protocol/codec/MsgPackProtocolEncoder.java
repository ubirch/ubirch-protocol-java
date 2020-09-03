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

import com.fasterxml.jackson.databind.node.TextNode;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolSigner;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePacker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Base64;

/**
 * The default msgpack protocol encoder.
 *
 * @author Matthias L. Jugel
 */
public class MsgPackProtocolEncoder extends ProtocolEncoder<byte[]> {
    private static MessagePack.PackerConfig config = new MessagePack.PackerConfig().withStr8FormatSupport(false);
    private static final MsgPackProtocolEncoder instance = new MsgPackProtocolEncoder();

    public static MsgPackProtocolEncoder getEncoder() {
        return instance;
    }

    final private MsgPackProtocolSigning protocolSigning = new MsgPackProtocolSigning() {
        @Override
        public void payloadConsumer(MessagePacker packer, ProtocolMessage pm, ByteArrayOutputStream out) throws IOException {
            // json4s
            // ------
            // To be able to return the payload as just bytes and not as base64 values, we have to
            // explicitly try to decode and pack the data in the msgpack.
            // There seems to be a limitation with the way json4s handles binary nodes.
            // https://gitlab.com/ubirch/ubirch-kafka-envelope/-/blob/master/src/main/scala/com/ubirch/kafka/package.scala#L166
            if (pm.getPayload() instanceof TextNode) {
                // write the payload
                try {
                    byte[] bytes = Base64.getDecoder().decode(pm.getPayload().asText());
                    packer.packBinaryHeader(bytes.length).addPayload(bytes);
                } catch (Exception e) {
                    super.payloadConsumer(packer, pm, out);
                }
            } else {
                super.payloadConsumer(packer, pm, out);
            }
        }
    };

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
            return encode(protocolSigning.sign(pm, signer));
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
