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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.UUID;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

/**
 * A ubirch-protocol message.
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public class ProtocolMessage {

    @JsonIgnore
    public final static int ubirchProtocolVersion = 1;

    @JsonIgnore
    public final static int PLAIN = ((ubirchProtocolVersion << 4) | 0x01);
    @JsonIgnore
    public final static int CHAINED = ((ubirchProtocolVersion << 4) | 0x03);
    @JsonIgnore
    public final static int SIGNED = ((ubirchProtocolVersion << 4) | 0x02);

    @JsonView(ProtocolMessageViews.Default.class)
    protected int version = 0;
    @JsonInclude(NON_NULL)
    @JsonView(ProtocolMessageViews.Default.class)
    protected UUID uuid = null;
    @JsonInclude(NON_NULL)
    @JsonView(ProtocolMessageViews.Default.class)
    protected byte[] chain = null;
    @JsonInclude(NON_NULL)
    @JsonView(ProtocolMessageViews.Default.class)
    protected int hint = 0;

    @JsonInclude(NON_NULL)
    @JsonView(ProtocolMessageViews.WithSignedData.class)
    protected byte[] signed;
    @JsonInclude(NON_NULL)
    @JsonView(ProtocolMessageViews.Default.class)
    protected byte[] signature = null;
    @JsonInclude(NON_NULL)
    @JsonView(ProtocolMessageViews.Default.class)
    protected JsonNode payload;

    public ProtocolMessage() {
    }

    public ProtocolMessage(int version, UUID uuid, int hint, Object payload) {
        this.version = version;
        this.uuid = uuid;
        this.hint = hint;
        this.payload = new ObjectMapper().valueToTree(payload);
    }

    public ProtocolMessage(int version, UUID uuid, byte[] chain, int hint, Object payload) {
        this(version, uuid, hint, payload);
        this.chain = chain;
    }

    @Override
    public String toString() {
        Base64.Encoder encoder = Base64.getEncoder();
        return "ProtocolMessage(" +
                String.format("v=0x%04x", version) +
                (uuid != null ? "," + uuid : "") +
                (chain != null ? String.format(",chain=%s", encoder.encodeToString(chain)) : "") +
                String.format(",hint=0x%02x", hint) +
                (payload != null ? ",p=" + payload : "") +
                (signed != null ? ",d=" + encoder.encodeToString(signed) : "") +
                (signature != null ? ",s=" + encoder.encodeToString(signature) : "") + ")";
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public UUID getUUID() {
        return uuid;
    }

    public void setUUID(UUID uuid) {
        this.uuid = uuid;
    }

    public byte[] getChain() {
        return chain;
    }

    public void setChain(byte[] chain) {
        this.chain = chain;
    }

    public int getHint() {
        return hint;
    }

    public void setHint(int hint) {
        this.hint = hint;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public byte[] getSigned() {
        return signed;
    }

    public void setSigned(byte[] data) {
        this.signed = data;
    }

    public JsonNode getPayload() {
        return payload;
    }

    public void setPayload(JsonNode payload) {
        this.payload = payload;
    }
}
