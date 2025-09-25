package uk.ac.nottingham.cryptography;

import uk.ac.nottingham.cryptography.banking.Bank;
import uk.ac.nottingham.cryptography.banking.BankTransaction;
import uk.ac.nottingham.cryptography.banking.InvalidTransactionException;
import uk.ac.nottingham.cryptography.hashing.SHA256;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/***
 * Length extension attack demo
 */
public class Main {
    public static void main(String[] args) throws IOException {

        // Authentication at Bank A
        String message = "from:20-60-40.23311492;to:35-01-17.11911597;stoken:7a2afc675906eb180ba2e18b;amount:1000";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        Bank A = new Bank();
        byte[] transactionAuthToken = A.authenticateTransaction(messageBytes);

        // Beginning of attack
        byte[] oldPadding = hexToBytes("8000000000000003b8");
        byte[] attackPayload = ";amount:100000".getBytes(StandardCharsets.UTF_8);
        byte[] newTransaction = concatBytes(messageBytes, oldPadding, attackPayload);
        byte[] newValidToken = SHA256.continueDigest(new ByteArrayInputStream(attackPayload), transactionAuthToken, 128);

        messageBytes = newTransaction;
        transactionAuthToken = newValidToken;
        // End of the attack

        // Verification at Bank B
        Bank B = new Bank();

        try {
            BankTransaction bt = B.verifyTransaction(messageBytes, transactionAuthToken);
            System.out.println("Authentication succeeded");
            System.out.printf("From: %s, To: %s%nAmount: %s",
                    bt.getFromAccount(),
                    bt.getToAccount(),
                    bt.getAmount());
        } catch (InvalidTransactionException ex) {
            System.err.println("Authentication failed");
        }
    }


    public static byte[] hexToBytes(String hex) {
        return java.util.HexFormat.of().parseHex(hex);
    }

    public static String bytesToHex(byte[] bytes)
    {
        return java.util.HexFormat.of().formatHex(bytes);
    }

    public static byte[] concatBytes(byte[] ... arrays) {
        int total = Arrays.stream(arrays).mapToInt(a -> a.length).sum();

        byte[] output = new byte[total];
        int position = 0;
        for(byte[] array : arrays) {
            System.arraycopy(array,0, output, position, array.length);
            position += array.length;
        }
        return output;
    }
}
