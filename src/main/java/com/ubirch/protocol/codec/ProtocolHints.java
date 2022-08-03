package com.ubirch.protocol.codec;

public class ProtocolHints {

    private ProtocolHints() {
        //not called
    }

    public static int HASHED_TRACKLE_MSG_PACK_HINT = 0x56;
    public static int TRACKLE_MSG_PACK_HINT = 0x54;
    public static int KEY_REGISTRATION_MSG_PACK_HINT = 0x01;
    public static int BINARY_OR_UNKNOWN_PAYLOAD_MSG_PACK_HINT = 0x00;
}
