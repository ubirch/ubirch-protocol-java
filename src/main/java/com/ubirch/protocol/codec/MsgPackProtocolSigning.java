package com.ubirch.protocol.codec;

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
 * This class acts a builder for the signing process:
 *
 * It defines the necessary methods for packing a 'Protocol Message' as stream of bytes
 * that are later signed.
 *
 * The expected way to provide a different packing process for each element of the
 * 'Protocol Message' is to override the method accordingly.
 *  - All methods that end in 'Consumer' are the building parts for the process.
 *  - The methods that perform the actual signing is 'sign';
 */
public class MsgPackProtocolSigning {

    private static final MessagePack.PackerConfig config = new MessagePack.PackerConfig().withStr8FormatSupport(false);

    public MsgPackProtocolSigning() { }

    public void versionConsumer(MessagePacker packer, ProtocolMessage pm) throws IOException {
        packer.packInt(pm.getVersion());
    }

    public void uuidConsumer(MessagePacker packer, ProtocolMessage pm) throws IOException {
        packer.packBinaryHeader(16).addPayload(UUIDUtil.uuidToBytes(pm.getUUID()));
    }

    public void chainConsumer(MessagePacker packer, ProtocolMessage pm) throws IOException {
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
    }

    public void hintConsumer(MessagePacker packer, ProtocolMessage pm) throws IOException {
        packer.packInt(pm.getHint());
    }

    public void payloadConsumer(MessagePacker packer, ProtocolMessage pm, ByteArrayOutputStream out) throws IOException {
        ObjectMapper mapper = new ObjectMapper(new MessagePackFactory());
        mapper.writeValue(out, pm.getPayload());
    }

    public ProtocolMessage sign(ProtocolMessage pm, ProtocolSigner signer) throws IOException, SignatureException, InvalidKeyException {
        //We prepare the streams and the packer
        ByteArrayOutputStream out = new ByteArrayOutputStream(255);
        MessagePacker packer = config.newPacker(out);
        packer.packArrayHeader(5 + (pm.getVersion() & 0x0f) - 2);

        //We build a stream based on the proper order for the Protocol Message
        versionConsumer(packer, pm);
        uuidConsumer(packer, pm);
        chainConsumer(packer, pm);
        hintConsumer(packer, pm);
        packer.flush(); // make sure everything is in the byte buffer
        payloadConsumer(packer, pm, out);
        packer.close(); // also closes out

        //We sign the bytes
        byte[] dataToSign = out.toByteArray();
        byte[] signature = signer.sign(pm.getUUID(), dataToSign, 0, dataToSign.length);

        //We set the values into the protocol message
        pm.setSigned(dataToSign);
        pm.setSignature(signature);
        return pm;
    }

}
