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

import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolSigner;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePacker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.SignatureException;

import static com.ubirch.protocol.codec.EncoderUtil.*;
import static com.ubirch.protocol.codec.ProtocolHints.HASHED_TRACKLE_MSG_PACK_HINT;

/**
 * This class acts a builder for the signing process:
 * <p>
 * It defines the necessary methods for packing a 'Protocol Message' as stream of bytes
 * that are later signed.
 * <p>
 * The expected way to provide a different packing process for each element of the
 * 'Protocol Message' is to override the method accordingly.
 * - All methods that end in 'Consumer' are the building parts for the process.
 * - The methods that perform the actual signing is 'sign';
 */
public class MsgPackProtocolSigning {

    private static final MessagePack.PackerConfig config = new MessagePack.PackerConfig().withStr8FormatSupport(false);

    public MsgPackProtocolSigning() {
    }

    public ProtocolMessage sign(ProtocolMessage pm, ProtocolSigner signer) throws IOException, SignatureException, InvalidKeyException {
        //We prepare the streams and the packer
        ByteArrayOutputStream out = new ByteArrayOutputStream(255);
        MessagePacker packer = config.newPacker(out);
        packer.packArrayHeader(5 + (pm.getVersion() & 0x0f) - 2);

        //We build a stream based on the proper order for the Protocol Message
        packVersion(packer, pm);
        packUUID(packer, pm);
        packChain(packer, pm);
        packHint(packer, pm);
        packer.flush(); // make sure everything is in the byte buffer
        packPayload(packer, pm, out);
        packer.close(); // also closes out

        //We sign the bytes
        byte[] dataToSign;
        if (pm.getHint() == HASHED_TRACKLE_MSG_PACK_HINT) {
            dataToSign = pm.getPayload().binaryValue();
        } else {
            dataToSign = out.toByteArray();
        }
        byte[] signature = signer.sign(pm.getUUID(), dataToSign, 0, dataToSign.length);

        //We set the values into the protocol message
        pm.setSigned(dataToSign);
        pm.setSignature(signature);
        return pm;
    }

}
