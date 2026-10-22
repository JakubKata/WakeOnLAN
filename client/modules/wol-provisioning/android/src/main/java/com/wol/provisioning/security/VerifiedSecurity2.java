// Copyright 2022 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Derived from Espressif esp-idf-provisioning-android lib-2.4.4 (b83b7854).
// Security fixes: propagate all authentication/crypto failures; require patch 1;
// validate response types/status/nonces; never reuse an AES-GCM nonce.
package com.wol.provisioning.security;

import com.espressif.provisioning.security.Security;
import espressif.Constants;


import com.espressif.provisioning.srp6a.BigIntegerUtils;
import com.espressif.provisioning.srp6a.SRP6CryptoParams;
import com.espressif.provisioning.srp6a.SRP6Exception;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import espressif.Sec2;
import espressif.Session;

/**
 * ESP-IDF Security 2: SRP-6a authentication and AES-256-GCM (patch 1).
 */
public class VerifiedSecurity2 implements Security {

    private static final int SESSION_STATE_REQUEST1 = 0;
    private static final int SESSION_STATE_RESPONSE1_REQUEST2 = 1;
    private static final int SESSION_STATE_RESPONSE2 = 2;
    private static final int SESSION_STATE_FINISHED = 3;

    private int sessionState = SESSION_STATE_REQUEST1;

    private String userName;

    private Cipher cipher;
    private VerifiedSrpClient client;

    private BigInteger clientPublicKey = null;
    private BigInteger devicePublicKey = null;
    private byte[] deviceNonce;
    private byte[] clientProof;
    private byte[] sharedKey;
    private byte[] key;
    private long counter;

    public VerifiedSecurity2(String username, String password, int patchVersion) {

        userName = username;
        if (patchVersion != 1) throw new IllegalArgumentException("Unsupported security patch");
        try {
            this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SecurityException("Provisioning authentication or encryption failed", e);
        }
        client = new VerifiedSrpClient();
        client.step1(username, password);
    }

    @Override
    public byte[] getNextRequestInSession(byte[] hexData) {
        byte[] request = null;
        switch (this.sessionState) {
            case SESSION_STATE_REQUEST1:
                this.sessionState = SESSION_STATE_RESPONSE1_REQUEST2;
                request = this.getStep0Request();
                break;
            case SESSION_STATE_RESPONSE1_REQUEST2:
                this.sessionState = SESSION_STATE_RESPONSE2;
                this.processStep0Response(hexData);
                request = this.getStep1Request();
                break;
            case SESSION_STATE_RESPONSE2:
                this.processStep1Response(hexData);
                this.sessionState = SESSION_STATE_FINISHED;
                break;
            default:
                throw new SecurityException("Handshake already complete");
        }
        return request;
    }

    private byte[] getStep0Request() {
        try {
            try {
                clientPublicKey = client.getClientPublicKey(SRP6CryptoParams.getInstance(3072, "SHA-512"));
            } catch (SRP6Exception e) {
                throw new SecurityException("Provisioning authentication or encryption failed", e);
            }
            byte[] publicKeyA = BigIntegerUtils.bigIntegerToBytes(clientPublicKey);

            Sec2.S2SessionCmd0 sessionCmd0 = Sec2.S2SessionCmd0
                    .newBuilder()
                    .setClientUsername(ByteString.copyFrom(userName.getBytes()))
                    .setClientPubkey(ByteString.copyFrom(publicKeyA))
                    .build();
            Sec2.Sec2Payload sec2Payload = Sec2.Sec2Payload
                    .newBuilder()
                    .setSc0(sessionCmd0)
                    .build();
            Session.SessionData sessionData = Session.SessionData
                    .newBuilder()
                    .setSecVer(Session.SecSchemeVersion.SecScheme2)
                    .setSec2(sec2Payload)
                    .build();
            return sessionData.toByteArray();
        } catch (Exception e) {
            throw new SecurityException("Provisioning authentication or encryption failed", e);
        }
    }

    private byte[] getStep1Request() {

        Sec2.S2SessionCmd1 sessionCmd1 = Sec2.S2SessionCmd1
                .newBuilder()
                .setClientProof(ByteString.copyFrom(clientProof))
                .build();
        Sec2.Sec2Payload sec1Payload = Sec2.Sec2Payload
                .newBuilder()
                .setSc1(sessionCmd1)
                .setMsg(Sec2.Sec2MsgType.S2Session_Command1)
                .build();
        Session.SessionData sessionData = Session.SessionData
                .newBuilder()
                .setSecVer(Session.SecSchemeVersion.SecScheme2)
                .setSec2(sec1Payload)
                .build();
        return sessionData.toByteArray();
    }

    private void processStep0Response(byte[] hexData) throws RuntimeException {

        try {
            if (hexData == null) {
                throw new SecurityException("No response from device");
            }
            Session.SessionData responseData = Session.SessionData.parseFrom(hexData);
            if (responseData.getSecVer() != Session.SecSchemeVersion.SecScheme2) {
                throw new SecurityException("Security version mismatch");
            }

            if (!responseData.hasSec2() || !responseData.getSec2().hasSr0()
                    || responseData.getSec2().getMsg() != Sec2.Sec2MsgType.S2Session_Response0
                    || responseData.getSec2().getSr0().getStatus() != Constants.Status.Success) {
                throw new SecurityException("Invalid SRP challenge");
            }
            byte[] deviceSalt = responseData.getSec2().getSr0().getDeviceSalt().toByteArray();
            byte[] devicePubKey = responseData.getSec2().getSr0().getDevicePubkey().toByteArray();

            if (deviceSalt.length != 16 || devicePubKey.length == 0 || devicePubKey.length > 384) {
                throw new SecurityException("Invalid SRP challenge length");
            }
            BigInteger salt = BigIntegerUtils.bigIntegerFromBytes(deviceSalt);
            devicePublicKey = BigIntegerUtils.bigIntegerFromBytes(devicePubKey);

            try {
                SRP6CryptoParams params = SRP6CryptoParams.getInstance(3072, "SHA-512");
                client.step2_for_client_evidence(params, salt, devicePublicKey, deviceSalt);
                clientProof = client.getClientProof();
            } catch (SRP6Exception e) {
                throw new SecurityException("Provisioning authentication or encryption failed", e);
            }
        } catch (InvalidProtocolBufferException e) {
            throw new SecurityException("Invalid handshake response", e);
        }
    }

    private void processStep1Response(byte[] hexData) throws RuntimeException {
        try {
            if (hexData == null) {
                throw new SecurityException("No response from device");
            }

            Session.SessionData responseData = Session.SessionData.parseFrom(hexData);
            if (responseData.getSecVer() != Session.SecSchemeVersion.SecScheme2) {
                throw new SecurityException("Security version mismatch");
            }

            if (!responseData.hasSec2() || !responseData.getSec2().hasSr1()
                    || responseData.getSec2().getMsg() != Sec2.Sec2MsgType.S2Session_Response1
                    || responseData.getSec2().getSr1().getStatus() != Constants.Status.Success) {
                throw new SecurityException("Invalid SRP proof");
            }
            byte[] deviceProof = responseData.getSec2().getSr1().getDeviceProof().toByteArray();
            deviceNonce = responseData.getSec2().getSr1().getDeviceNonce().toByteArray();

            if (deviceProof.length != 64 || deviceNonce.length != 12) {
                throw new SecurityException("Invalid proof or nonce length");
            }
            try {
                client.step3(BigIntegerUtils.bigIntegerFromBytes(deviceProof));
            } catch (SRP6Exception e) {
                throw new SecurityException("Provisioning authentication or encryption failed", e);
            }

            sharedKey = client.getSharedKey();
            key = Arrays.copyOfRange(sharedKey, 0, 32);

            counter = ((deviceNonce[8] & 0xFFL) << 24) | ((deviceNonce[9] & 0xFFL) << 16) | ((deviceNonce[10] & 0xFFL) << 8) | (deviceNonce[11] & 0xFFL);

        } catch (InvalidProtocolBufferException e) {
            throw new SecurityException("Invalid handshake response", e);
        }
    }

    public byte[] encrypt(byte[] data) {

        requireSession();
        // Device nonce = IV
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        byte[] nonce = new byte[12];
        System.arraycopy(deviceNonce, 0, nonce, 0, 8);
        System.arraycopy(intToBigEndian((int) counter), 0, nonce, 8, 4);
        counter++;
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);

        try {
            this.cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, parameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SecurityException("Provisioning authentication or encryption failed", e);
        } catch (InvalidKeyException e) {
            throw new SecurityException("Provisioning authentication or encryption failed", e);
        }

        try {
            return this.cipher.doFinal(data);
        } catch (BadPaddingException e) {
            throw new SecurityException("Provisioning authentication or encryption failed", e);
        } catch (IllegalBlockSizeException e) {
            throw new SecurityException("Provisioning authentication or encryption failed", e);
        }
    }

    public byte[] decrypt(byte[] data) {
        requireSession();

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        byte[] nonce = new byte[12];
        System.arraycopy(deviceNonce, 0, nonce, 0, 8);
        System.arraycopy(intToBigEndian((int) counter), 0, nonce, 8, 4);
        counter++;
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);

        try {
            this.cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, parameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SecurityException("Provisioning authentication or encryption failed", e);
        } catch (InvalidKeyException e) {
            throw new SecurityException("Provisioning authentication or encryption failed", e);
        }

        try {
            return this.cipher.doFinal(data);
        } catch (BadPaddingException e) {
            throw new SecurityException("Provisioning authentication or encryption failed", e);
        } catch (IllegalBlockSizeException e) {
            throw new SecurityException("Provisioning authentication or encryption failed", e);
        }
    }

    private void requireSession() {
        if (sessionState != SESSION_STATE_FINISHED || counter > 0xffffffffL) {
            throw new SecurityException("Session is not usable");
        }
    }

    private byte[] intToBigEndian(int value) {
        return new byte[]{
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }
}
