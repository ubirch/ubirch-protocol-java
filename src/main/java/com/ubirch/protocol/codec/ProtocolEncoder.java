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

import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolSigner;

import java.security.SignatureException;

/**
 * Protocol encoder interface.
 *
 * @param <T> the target type to encode to
 * @author Matthias L. Jugel
 */
abstract class ProtocolEncoder<T> {
    /**
     * Encode a protocol message into the target type.
     *
     * @param pm     the protocol message to encode from
     * @param signer a protocol signer taking care of the crypto operations to sign the final message
     * @return the encoded and signed message
     * @throws ProtocolException  if the encoding fails for some reason
     * @throws SignatureException if the signature cannot be created
     */
    abstract T encode(ProtocolMessage pm, ProtocolSigner signer) throws ProtocolException, SignatureException;

    /**
     * Re-assemble the protocol message into the target type.
     *
     * @param pm the protocol message to encode from
     * @return the encoded message with the existing signature
     * @throws ProtocolException if the message cannot be encoded from the input
     */
    abstract T encode(ProtocolMessage pm) throws ProtocolException;

    void checkProtocolMessage(ProtocolMessage pm) throws ProtocolException {
        if (pm.getSignature() == null) {
            throw new ProtocolException("missing signature");
        }
        if (pm.getSigned() == null) {
            throw new ProtocolException("missing signed data");
        }

        int protocolVersion = pm.getVersion();
        if (protocolVersion != ProtocolMessage.SIGNED && protocolVersion != ProtocolMessage.CHAINED) {
            throw new ProtocolException(String.format("unknown protocol version: 0x%x", pm.getVersion()));
        }
    }
}