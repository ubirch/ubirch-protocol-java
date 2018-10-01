package com.ubirch.protocol.codec;

import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * Utility class for handling UUID and bytes
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public class UUIDUtil {
	public static byte[] uuidToBytes(UUID uuid) {
		ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
		bb.putLong(uuid.getMostSignificantBits());
		bb.putLong(uuid.getLeastSignificantBits());
		return bb.array();
	}

	public static UUID bytesToUUID(byte[] bytes) {
		ByteBuffer bb = ByteBuffer.wrap(bytes);
		long high = bb.getLong();
		long low = bb.getLong();
		return new UUID(high, low);
	}
}
