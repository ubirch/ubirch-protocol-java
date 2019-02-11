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
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;

import java.io.IOException;

/**
 * Simple JSON protocol decoder.
 *
 * @author Matthias L. Jugel
 */
public class JSONProtocolDecoder extends ProtocolDecoder<String> {
    private static JSONProtocolDecoder instance = new JSONProtocolDecoder();

    public static JSONProtocolDecoder getDecoder() {
        return instance;
    }

    private ObjectMapper mapper;
    JSONProtocolDecoder() {
        mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS, true);
    }

    public ProtocolMessage decode(String message) throws ProtocolException {
        try {
            ProtocolMessage pm = mapper.readValue(message, ProtocolMessage.class);
            if (pm.getPayload() != null) {
                pm.setSigned(mapper.writeValueAsBytes(pm.getPayload()));
            }
            return pm;
        } catch (JsonProcessingException e) {
            throw new ProtocolException("extraction of signed data failed", e);
        } catch (IOException e) {
            throw new ProtocolException("json decoding failed", e);
        }
    }
}
