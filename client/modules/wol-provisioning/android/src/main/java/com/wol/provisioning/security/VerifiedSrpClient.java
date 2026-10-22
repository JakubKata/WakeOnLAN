// Copyright 2022 Espressif Systems (Shanghai) PTE LTD
// Copyright (c) Connect2id Ltd. and others, 2011 - 2019
// SPDX-License-Identifier: Apache-2.0
//
// Adapted from esp-idf-provisioning-android lib-2.4.4 SRP6ClientSession and
// ClientSRP6Routines. Uses the SDK's SRP arithmetic, retaining salt and SHA-512
// outputs as bytes: BigInteger serialization must not discard leading zeros.
package com.wol.provisioning.security;

import com.espressif.provisioning.srp6a.BigIntegerUtils;
import com.espressif.provisioning.srp6a.SRP6ClientCredentials;
import com.espressif.provisioning.srp6a.SRP6CryptoParams;
import com.espressif.provisioning.srp6a.SRP6Exception;
import com.espressif.provisioning.srp6a.SRP6Routines;
import com.espressif.provisioning.srp6a.XRoutineWithUserIdentity;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/** The fixed ESP-IDF SRP-6a/SHA-512 profile, with lossless wire encoding. */
public final class VerifiedSrpClient {
    private final SRP6Routines routines = new SRP6Routines();
    private final SecureRandom random;
    private int state;
    private String username;
    private String password;
    private SRP6CryptoParams params;
    private BigInteger privateValue;
    private BigInteger publicValue;
    private byte[] sharedKey;
    private byte[] clientProof;
    private byte[] serverProof;

    public VerifiedSrpClient() { this(new SecureRandom()); }

    // Package-private injection is only used by deterministic interoperability tests.
    VerifiedSrpClient(SecureRandom random) { this.random = random; }

    public void step1(String username, String password) {
        requireState(0);
        if (username == null || username.isEmpty() || password == null) {
            throw new IllegalArgumentException("Missing provisioning credentials");
        }
        this.username = username;
        this.password = password;
        state = 1;
    }

    public BigInteger getClientPublicKey(SRP6CryptoParams params) throws SRP6Exception {
        requireState(1);
        SRP6CryptoParams expected = SRP6CryptoParams.getInstance(3072, "SHA-512");
        if (params == null || !expected.N.equals(params.N) || !expected.g.equals(params.g)
                || !expected.H.equals(params.H)) {
            throw new IllegalArgumentException("Unsupported SRP profile");
        }
        this.params = params;
        privateValue = routines.generatePrivateValue(params.N, random);
        publicValue = routines.computePublicClientValue(params.N, params.g, privateValue);
        state = 2;
        return publicValue;
    }

    public SRP6ClientCredentials step2_for_client_evidence(
            SRP6CryptoParams config, BigInteger saltValue, BigInteger devicePublicKey, byte[] salt)
            throws SRP6Exception {
        requireState(2);
        state = -1; // A failed challenge permanently invalidates this session.
        if (config == null || !config.N.equals(params.N) || !config.g.equals(params.g)
                || !config.H.equals(params.H) || salt == null || salt.length != 16
                || !new BigInteger(1, salt).equals(saltValue)
                || devicePublicKey == null || devicePublicKey.signum() <= 0
                || devicePublicKey.compareTo(params.N) >= 0) {
            throw new SRP6Exception("Invalid SRP challenge", SRP6Exception.CauseType.BAD_PUBLIC_VALUE);
        }
        MessageDigest digest = params.getMessageDigestInstance();
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        BigInteger x;
        try {
            x = new XRoutineWithUserIdentity().computeX(digest, salt,
                    username.getBytes(StandardCharsets.UTF_8), passwordBytes);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            password = null;
        }
        BigInteger k = routines.computeK(digest, params.N, params.g);
        BigInteger u = routines.computeU(digest, params.N, publicValue, devicePublicKey);
        if (u.signum() == 0) {
            throw new SRP6Exception("Invalid SRP challenge", SRP6Exception.CauseType.BAD_PUBLIC_VALUE);
        }
        BigInteger sessionKey = routines.computeSessionKey(
                params.N, params.g, k, x, u, privateValue, devicePublicKey);
        privateValue = null;
        sharedKey = digest.digest(BigIntegerUtils.bigIntegerToBytes(sessionKey));

        byte[] modulus = BigIntegerUtils.bigIntegerToBytes(params.N);
        byte[] generator = fixedWidth(params.g, modulus.length);
        byte[] xor = digest.digest(modulus);
        byte[] generatorHash = digest.digest(generator);
        for (int i = 0; i < xor.length; i++) xor[i] ^= generatorHash[i];
        byte[] identityHash = digest.digest(username.getBytes(StandardCharsets.UTF_8));
        byte[] publicBytes = BigIntegerUtils.bigIntegerToBytes(publicValue);
        digest.update(xor);
        digest.update(identityHash);
        digest.update(salt);
        digest.update(publicBytes);
        digest.update(BigIntegerUtils.bigIntegerToBytes(devicePublicKey));
        clientProof = digest.digest(sharedKey);
        digest.update(publicBytes);
        digest.update(clientProof);
        serverProof = digest.digest(sharedKey);
        state = 3;
        return new SRP6ClientCredentials(publicValue, new BigInteger(1, clientProof));
    }

    public void step3(BigInteger proof) throws SRP6Exception {
        requireState(3);
        state = -1;
        if (proof == null || proof.signum() < 0 || proof.bitLength() > 512
                || !MessageDigest.isEqual(serverProof, fixedWidth(proof, 64))) {
            Arrays.fill(sharedKey, (byte) 0);
            throw new SRP6Exception("Bad server credentials", SRP6Exception.CauseType.BAD_CREDENTIALS);
        }
        state = 4;
    }

    public byte[] getClientProof() {
        requireState(3);
        return clientProof.clone();
    }

    public byte[] getSharedKey() {
        requireState(4);
        return sharedKey.clone();
    }

    private void requireState(int expected) {
        if (state != expected) throw new IllegalStateException("Invalid SRP session state");
    }

    private static byte[] fixedWidth(BigInteger value, int width) {
        byte[] source = BigIntegerUtils.bigIntegerToBytes(value);
        if (source.length > width) throw new IllegalArgumentException("Oversized SRP value");
        byte[] result = new byte[width];
        System.arraycopy(source, 0, result, width - source.length, source.length);
        return result;
    }
}
