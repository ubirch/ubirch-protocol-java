package com.ubirch.protocol.codec;

import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolVerifier;

import java.security.SignatureException;

/**
 * Protocol decoder interface is the basis for protocol decoders.
 * Generally they will decode to a {@link ProtocolMessage}, but in case of a verification, may also
 * return a special envelope type with extra information.
 *
 * @param <T> the type of the source message
 * @author Matthias L. Jugel
 */
public interface ProtocolDecoder<T> {
	/**
	 * Decode and verify this message.
	 *
	 * @param message  the message to decode
	 * @param verifier a {@link ProtocolVerifier} that takes care of cryptographically verifying the message signature
	 * @return the decoded and verified data as an envelope type
	 * @throws ProtocolException if some json processing issue occurs, or the crypto functions fail (no signature verification)
	 * @throws SignatureException if the signature verification cannot be done for some reason
	 */
	ProtocolMessage decode(T message, ProtocolVerifier verifier) throws ProtocolException, SignatureException;

	/**
	 * Decode a protocol messsage without decoding, just taking the pieces apart.
	 *
	 * @param message the message to decode
	 * @return the decoded message as a {@link ProtocolMessage}
	 * @throws ProtocolException if json decoding fails
	 */
	ProtocolMessage decode(T message) throws ProtocolException;
}
