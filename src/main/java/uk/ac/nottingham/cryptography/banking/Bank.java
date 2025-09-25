package uk.ac.nottingham.cryptography.banking;

import uk.ac.nottingham.cryptography.hashing.SHA256;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Bank {
    private String key = "5a95b9feba8efda0b6c3c6a96ad05a87";

    public byte[] authenticateTransaction(byte[] transaction) throws IOException {
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] km = new byte[keyBytes.length + transaction.length];
        System.arraycopy(keyBytes, 0, km, 0, keyBytes.length);
        System.arraycopy(transaction, 0, km, keyBytes.length, transaction.length);
        return SHA256.digest(new ByteArrayInputStream(km));
    }

    public BankTransaction verifyTransaction(byte[] transaction, byte[] authToken) throws InvalidTransactionException {
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] km = new byte[keyBytes.length + transaction.length];
        System.arraycopy(keyBytes, 0, km, 0, keyBytes.length);
        System.arraycopy(transaction, 0, km, keyBytes.length, transaction.length);

        try {
            byte[] computedToken = SHA256.digest(new ByteArrayInputStream(km));

            if (!Arrays.equals(computedToken, authToken)) {
                throw new InvalidTransactionException("Invalid authentication token");
            }
        } catch (IOException ex) {
            throw new InvalidTransactionException("Could not load transaction bytes");
        }

        return new BankTransaction(new String(transaction, StandardCharsets.UTF_8));
    }

    private static byte[] hexToBytes(String hex) {
        return java.util.HexFormat.of().parseHex(hex);
    }

    private static String bytesToHex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }

}
