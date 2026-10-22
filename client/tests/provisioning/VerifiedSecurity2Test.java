package com.wol.provisioning.security;

import com.google.protobuf.ByteString;
import espressif.Constants;
import espressif.Sec2;
import espressif.Session;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Full protobuf handshake and AES-GCM checks against independently generated ESP-IDF vectors. */
public final class VerifiedSecurity2Test {
    private static final byte[] NONCE = hex("010203040506070800000001");
    private static int assertions;

    public static void main(String[] args) throws Exception {
        try (var paths = Files.list(Path.of(args[0]))) {
            for (Path path : paths.filter(p -> p.toString().endsWith(".properties")).sorted().toList()) {
                Properties vector = new Properties();
                try (var input = Files.newInputStream(path)) { vector.load(input); }
                runVector(vector);
                System.out.println("Security2 handshake/GCM: " + path.getFileName() + " passed");
            }
        }
        mustFail(() -> new VerifiedSecurity2("user", "password", 0));
        System.out.println("VerifiedSecurity2: " + assertions + " assertions passed");
    }

    private static void runVector(Properties vector) throws Exception {
        VerifiedSecurity2 session = challenged(vector);
        byte[] response = response1(vector, NONCE, hex(vector.getProperty("M2")));
        check(session.getNextRequestInSession(response) == null, "Handshake must finish");
        byte[] plaintext = "test-only-wifi-password".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] key = Arrays.copyOf(hex(vector.getProperty("K")), 32);
        byte[] ciphertext = session.encrypt(plaintext);
        check(Arrays.equals(ciphertext, crypt(Cipher.ENCRYPT_MODE, key, NONCE, plaintext)), "Client AES-GCM differs from reference");
        byte[] replyNonce = NONCE.clone(); replyNonce[11] = 2;
        byte[] reply = crypt(Cipher.ENCRYPT_MODE, key, replyNonce, plaintext);
        check(Arrays.equals(plaintext, session.decrypt(reply)), "Server AES-GCM differs from reference");
        mustFail(() -> session.decrypt(reply)); // A replay has an old nonce.

        VerifiedSecurity2 altered = completed(vector);
        byte[] badCiphertext = crypt(Cipher.ENCRYPT_MODE, key, NONCE, plaintext);
        badCiphertext[0] ^= 1;
        mustFail(() -> altered.decrypt(badCiphertext));

        VerifiedSecurity2 wrongProof = challenged(vector);
        byte[] proof = hex(vector.getProperty("M2")); proof[0] ^= 1;
        mustFail(() -> wrongProof.getNextRequestInSession(response1(vector, NONCE, proof)));
        VerifiedSecurity2 badNonce = challenged(vector);
        mustFail(() -> badNonce.getNextRequestInSession(response1(vector, new byte[11], hex(vector.getProperty("M2")))));
        VerifiedSecurity2 invalidStatus = started(vector);
        byte[] denied = Session.SessionData.newBuilder().setSecVer(Session.SecSchemeVersion.SecScheme2)
                .setSec2(Sec2.Sec2Payload.newBuilder().setMsg(Sec2.Sec2MsgType.S2Session_Response0)
                        .setSr0(Sec2.S2SessionResp0.newBuilder().setStatus(Constants.Status.CryptoError))).build().toByteArray();
        mustFail(() -> invalidStatus.getNextRequestInSession(denied));
        VerifiedSecurity2 downgrade = started(vector);
        mustFail(() -> downgrade.getNextRequestInSession(Session.SessionData.newBuilder()
                .setSecVer(Session.SecSchemeVersion.SecScheme1).build().toByteArray()));
        VerifiedSecurity2 malformed = started(vector);
        mustFail(() -> malformed.getNextRequestInSession(new byte[] {(byte) 0xff}));
        VerifiedSecurity2 exhausted = completed(vector);
        field("counter").setLong(exhausted, 0x1_0000_0000L);
        mustFail(() -> exhausted.encrypt(plaintext));
        mustFail(() -> exhausted.decrypt(reply));
    }

    private static VerifiedSecurity2 started(Properties vector) throws Exception {
        VerifiedSecurity2 result = new VerifiedSecurity2(vector.getProperty("username"), vector.getProperty("password"), 1);
        byte[] privateValue = hex(vector.getProperty("a").length() % 2 == 0 ? vector.getProperty("a") : "0" + vector.getProperty("a"));
        VerifiedSrpClient client = new VerifiedSrpClient(new SecureRandom() {
            @Override public void nextBytes(byte[] bytes) {
                Arrays.fill(bytes, (byte) 0);
                System.arraycopy(privateValue, 0, bytes, bytes.length - privateValue.length, privateValue.length);
            }
        });
        client.step1(vector.getProperty("username"), vector.getProperty("password"));
        field("client").set(result, client);
        Session.SessionData request = Session.SessionData.parseFrom(result.getNextRequestInSession(null));
        check(request.getSecVer() == Session.SecSchemeVersion.SecScheme2, "Client must require Security 2");
        check(Arrays.equals(request.getSec2().getSc0().getClientPubkey().toByteArray(), hex(vector.getProperty("A"))), "Public key differs");
        return result;
    }

    private static VerifiedSecurity2 challenged(Properties vector) throws Exception {
        VerifiedSecurity2 result = started(vector);
        byte[] response = Session.SessionData.newBuilder().setSecVer(Session.SecSchemeVersion.SecScheme2)
                .setSec2(Sec2.Sec2Payload.newBuilder().setMsg(Sec2.Sec2MsgType.S2Session_Response0)
                        .setSr0(Sec2.S2SessionResp0.newBuilder().setStatus(Constants.Status.Success)
                                .setDeviceSalt(ByteString.copyFrom(hex(vector.getProperty("salt"))))
                                .setDevicePubkey(ByteString.copyFrom(hex(vector.getProperty("B"))))))
                .build().toByteArray();
        Session.SessionData proof = Session.SessionData.parseFrom(result.getNextRequestInSession(response));
        check(Arrays.equals(proof.getSec2().getSc1().getClientProof().toByteArray(), hex(vector.getProperty("M1"))), "SRP proof differs");
        return result;
    }

    private static VerifiedSecurity2 completed(Properties vector) throws Exception {
        VerifiedSecurity2 result = challenged(vector);
        check(result.getNextRequestInSession(response1(vector, NONCE, hex(vector.getProperty("M2")))) == null, "Incomplete handshake");
        return result;
    }

    private static byte[] response1(Properties vector, byte[] nonce, byte[] proof) {
        return Session.SessionData.newBuilder().setSecVer(Session.SecSchemeVersion.SecScheme2)
                .setSec2(Sec2.Sec2Payload.newBuilder().setMsg(Sec2.Sec2MsgType.S2Session_Response1)
                        .setSr1(Sec2.S2SessionResp1.newBuilder().setStatus(Constants.Status.Success)
                                .setDeviceProof(ByteString.copyFrom(proof)).setDeviceNonce(ByteString.copyFrom(nonce))))
                .build().toByteArray();
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] value) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(value);
    }
    private static Field field(String name) throws Exception { Field field = VerifiedSecurity2.class.getDeclaredField(name); field.setAccessible(true); return field; }
    private static byte[] hex(String value) { return HexFormat.of().parseHex(value); }
    private static void check(boolean value, String message) { assertions++; if (!value) throw new AssertionError(message); }
    private static void mustFail(Checked action) throws Exception {
        assertions++;
        try { action.run(); } catch (SecurityException | IllegalArgumentException | IllegalStateException expected) { return; }
        throw new AssertionError("Unsafe input was accepted");
    }
    interface Checked { void run() throws Exception; }
}
