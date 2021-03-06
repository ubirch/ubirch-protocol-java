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

package com.ubirch.protocol;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.UUID;

/**
 * Interface for implementing specific crypto for protocol verification.
 *
 * @author Matthias L. Jugel
 */
public interface ProtocolVerifier {
    /**
     * Sign the protocol message and return the updated message with the signature.
     *
     * @param uuid      the uuid to identify the public key to verify the message
     * @param data      the data to verify
     * @param offset    the offset into the data
     * @param len       the length of the data to verify
     * @param signature the signature to verify against
     * @return whether the signature can be verified given the uuid and data
     * @throws SignatureException  if the verification fails for initialization or other issues
     * @throws InvalidKeyException if the verification fails because the key is invalid
     */
    boolean verify(UUID uuid, byte[] data, int offset, int len, byte[] signature) throws SignatureException, InvalidKeyException;
}
