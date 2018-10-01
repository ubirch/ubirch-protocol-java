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

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.UUID;

/**
 * Interface for implementing specific crypto for protocol signing.
 *
 * @author Matthias L. Jugel
 */
public interface ProtocolSigner {
	/**
	 * Sign the protocol message and return the updated message with the signature.
	 *
	 * @param uuid   the uuid to identify the public key to sign the message
	 * @param data   the data to sign
	 * @param offset the offset into the data
	 * @param len    the length of the data to sign
	 * @return the generated signature
	 * @throws SignatureException  if the signing process fails
	 * @throws InvalidKeyException if the signing process fails because of an invalid private key
	 */
	byte[] sign(UUID uuid, byte[] data, int offset, int len) throws SignatureException, InvalidKeyException;
}
