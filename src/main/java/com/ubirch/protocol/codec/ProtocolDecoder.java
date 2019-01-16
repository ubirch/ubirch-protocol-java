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
import com.ubirch.protocol.ProtocolVerifier;

import java.security.InvalidKeyException;
import java.security.SignatureException;

/**
 * Protocol decoder interface is the basis for protocol decoders.
 * Generally they will decode to a {@link ProtocolMessage}, but in case of a verification, may also
 * return a special envelope type with extra information.
 *
 * @param <T> the type of the source message
 * @author Matthias L. Jugel
 */
abstract class ProtocolDecoder<T> {
    /**
     * Decode and verify this message.
     *
     * @param message  the message to decode
     * @param verifier a {@link ProtocolVerifier} that takes care of cryptographically verifying the message signature
     * @return the decoded and verified data as an envelope type
     * @throws ProtocolException  if some json processing issue occurs, or the crypto functions fail (no signature verification)
     * @throws SignatureException if the signature verification cannot be done for some reason
     */
    public ProtocolMessage decode(T message, ProtocolVerifier verifier) throws ProtocolException, SignatureException {
        ProtocolMessage pm = decode(message);
        try {
            if (!verifier.verify(pm.getUUID(), pm.getSigned(), 0, pm.getSigned().length, pm.getSignature())) {
                throw new SignatureException(String.format("signature verification failed: %s", pm));
            }
            return pm;
        } catch (InvalidKeyException e) {
            throw new ProtocolException("invalid key", e);
        }
    }

    /**
     * Decode a protocol messsage without decoding, just taking the pieces apart.
     *
     * @param message the message to decode
     * @return the decoded message as a {@link ProtocolMessage}
     * @throws ProtocolException if json decoding fails
     */
    abstract ProtocolMessage decode(T message) throws ProtocolException;
}
