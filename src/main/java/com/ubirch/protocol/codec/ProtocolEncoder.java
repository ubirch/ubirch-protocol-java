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
public interface ProtocolEncoder<T> {
	/**
	 * Encode a protocol message into the target type.
	 * @param pm the protocol message to encode from
	 * @param signer a protocol signer taking care of the crypto operations to sign the final message
	 * @return the encoded and signed message
	 * @throws ProtocolException if the encoding fails for some reason
	 * @throws SignatureException if the signature cannot be created
	 */
	T encode(ProtocolMessage pm, ProtocolSigner signer) throws ProtocolException, SignatureException;
}
