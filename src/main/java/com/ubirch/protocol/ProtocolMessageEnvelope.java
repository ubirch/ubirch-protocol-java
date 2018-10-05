package com.ubirch.protocol;

import com.fasterxml.jackson.annotation.JsonValue;
import org.apache.commons.codec.binary.Hex;

/**
 * Add description.
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public class ProtocolMessageEnvelope {
	protected byte[] raw = null;
	protected ProtocolMessage message;

	public ProtocolMessageEnvelope(ProtocolMessage pm) {
		this.setMessage(pm);
	}

	public ProtocolMessageEnvelope(ProtocolMessage pm, byte[] raw) {
		this.setMessage(pm);
		this.setRaw(raw);
	}

	@Override
	public String toString() {
		return "Envelope(" + getMessage() + (getRaw() != null ? "," + Hex.encodeHexString(getRaw()) : "") + ")";
	}

	public byte[] getRaw() {
		return raw;
	}

	public void setRaw(byte[] raw) {
		this.raw = raw;
	}

	public ProtocolMessage getMessage() {
		return message;
	}

	public void setMessage(ProtocolMessage message) {
		this.message = message;
	}
}
