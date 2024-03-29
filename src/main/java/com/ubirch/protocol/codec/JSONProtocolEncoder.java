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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolMessageViews;
import com.ubirch.protocol.ProtocolSigner;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.SignatureException;

/**
 * Simpe JSON protocol encoder.
 *
 * @author Matthias L. Jugel
 */
@SuppressWarnings("WeakerAccess")
public class JSONProtocolEncoder extends ProtocolEncoder<String> {
    private static JSONProtocolEncoder instance = new JSONProtocolEncoder();
    private JsonMapper mapper = JsonMapper.builder()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .configure(MapperFeature.DEFAULT_VIEW_INCLUSION, false).build();

    public JSONProtocolEncoder() {
        mapper.setConfig(mapper.getSerializationConfig().withView(ProtocolMessageViews.Default.class));
    }

    public static JSONProtocolEncoder getEncoder() {
        return instance;
    }

    @Override
    public String encode(ProtocolMessage pm, ProtocolSigner signer) throws ProtocolException, SignatureException {
        if (pm == null || signer == null) {
            throw new IllegalArgumentException("message or signer null");
        }

        try {
            pm.setSigned(this.mapper.writeValueAsBytes(pm.getPayload()));
            pm.setSignature(signer.sign(pm.getUUID(), pm.getSigned(), 0, pm.getSigned().length));
            return encode(pm);
        } catch (InvalidKeyException e) {
            throw new ProtocolException("invalid key", e);
        } catch (JsonProcessingException e) {
            throw new ProtocolException("json encoding failed", e);
        }
    }

    @Override
    public String encode(ProtocolMessage pm) throws ProtocolException {
        checkProtocolMessage(pm);

        try {
            pm.setSignature(pm.getSignature());
            return new String(mapper.writeValueAsBytes(pm), StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new ProtocolException("json encoding failed", e);
        }
    }
}
