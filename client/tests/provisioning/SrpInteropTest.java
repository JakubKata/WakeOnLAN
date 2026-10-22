package com.wol.provisioning.security;

import com.espressif.provisioning.srp6a.SRP6CryptoParams;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Properties;

/** Standalone JVM interoperability test; no Android, Gradle or test framework needed. */
public final class SrpInteropTest {
    private static final SRP6CryptoParams PARAMS = SRP6CryptoParams.getInstance(3072, "SHA-512");

    public static void main(String[] files) throws Exception {
        for (String filename : files) {
            Properties vector = new Properties();
            try (InputStream input = Files.newInputStream(Path.of(filename))) { vector.load(input); }
            verify(vector);
            System.out.println("PASS " + Path.of(filename).getFileName());
        }
    }

    private static void verify(Properties vector) throws Exception {
        VerifiedSrpClient client = challenge(vector, vector.getProperty("password"));
        equal(bytes(vector, "M1"), client.getClientProof(), "client proof");
        expectFailure(client::getSharedKey, "key exposed before authentication");
        client.step3(integer(vector, "M2"));
        equal(bytes(vector, "K"), client.getSharedKey(), "shared key");
        expectFailure(() -> client.step3(integer(vector, "M2")), "proof replay");

        VerifiedSrpClient tampered = challenge(vector, vector.getProperty("password"));
        expectFailure(() -> tampered.step3(integer(vector, "M2").xor(BigInteger.ONE)), "tampered proof");
        expectFailure(tampered::getSharedKey, "key exposed after authentication failure");
        expectFailure(() -> tampered.step3(integer(vector, "M2")), "failed session reused");

        VerifiedSrpClient wrongPassword = challenge(vector, "incorrect-password-for-test");
        if (Arrays.equals(bytes(vector, "M1"), wrongPassword.getClientProof())) {
            throw new AssertionError("Incorrect password produced the valid proof");
        }
        expectFailure(() -> wrongPassword.step3(integer(vector, "M2")), "wrong password");

        VerifiedSrpClient invalidPublic = start(vector, vector.getProperty("password"));
        expectFailure(() -> invalidPublic.step2_for_client_evidence(
                PARAMS, integer(vector, "salt"), BigInteger.ZERO, bytes(vector, "salt")), "zero public key");
        expectFailure(invalidPublic::getSharedKey, "key exposed after bad public key");
    }

    private static VerifiedSrpClient start(Properties vector, String password) throws Exception {
        byte[] privateBytes = bytes(vector, "a");
        VerifiedSrpClient client = new VerifiedSrpClient(new SecureRandom() {
            @Override public void nextBytes(byte[] output) {
                Arrays.fill(output, (byte) 0);
                System.arraycopy(privateBytes, 0, output, output.length - privateBytes.length, privateBytes.length);
            }
        });
        client.step1(vector.getProperty("username"), password);
        if (!integer(vector, "A").equals(client.getClientPublicKey(PARAMS))) {
            throw new AssertionError("Incorrect public key");
        }
        return client;
    }

    private static VerifiedSrpClient challenge(Properties vector, String password) throws Exception {
        VerifiedSrpClient client = start(vector, password);
        client.step2_for_client_evidence(SRP6CryptoParams.getInstance(3072, "SHA-512"),
                integer(vector, "salt"), integer(vector, "B"), bytes(vector, "salt"));
        return client;
    }

    private static byte[] bytes(Properties properties, String name) {
        return HexFormat.of().parseHex(properties.getProperty(name));
    }

    private static BigInteger integer(Properties properties, String name) {
        return new BigInteger(1, bytes(properties, name));
    }

    private static void equal(byte[] expected, byte[] actual, String name) {
        if (!Arrays.equals(expected, actual)) throw new AssertionError("Incorrect " + name);
    }

    private interface Action { void run() throws Exception; }

    private static void expectFailure(Action action, String message) throws Exception {
        try { action.run(); }
        catch (IllegalArgumentException | IllegalStateException | com.espressif.provisioning.srp6a.SRP6Exception expected) {
            return;
        }
        throw new AssertionError(message);
    }
}
