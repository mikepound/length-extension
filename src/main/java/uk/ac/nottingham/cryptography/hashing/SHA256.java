package uk.ac.nottingham.cryptography.hashing;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.LinkedList;

import static uk.ac.nottingham.cryptography.Main.bytesToHex;

public class SHA256 {
    private static final int[] H0 = new int[] {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
    };

    private static final int[] K = new int[]{
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private SHA256() {

    }

    public static void initialiseState(int[] state) {
        System.arraycopy(H0, 0, state, 0, 8);
    }

    public static void expandWords(int[] messageBlock, int[] words) {
        // Copy first 16 words unchanged
        System.arraycopy(messageBlock, 0, words, 0, 16);

        // Remaining words calculated from previous words
        for (int i = 16; i < 64; i++) {
            int im15 = words[i - 15];
            int im2 = words[i - 2];
            int s0 = rotr(im15, 7) ^ rotr(im15, 18) ^ (im15 >>> 3);
            int s1 = rotr(im2, 17) ^ rotr(im2, 19) ^ (im2 >>> 10);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
    }

    public static void compressionFunction(int[] state, int[] words) {
        int a = state[0], b = state[1], c = state[2], d = state[3], e = state[4],
                f = state[5], g = state[6], h = state[7];

        // Loop
        for (int i = 0; i < 64; i++) {
            int s0 = rotr(a,2) ^ rotr(a, 13) ^ rotr(a,22);
            int s1 = rotr(e,6) ^ rotr(e, 11) ^ rotr(e,25);
            int ch = (e & f) ^ ((~e) & g);
            int ma = (a & b) ^ (a & c) ^ (b & c);
            int hprime1 = h + words[i] + K[i] + ch + s1;
            int hprime2 = ma + s0;
            h = g;
            g = f;
            f = e;
            e = d + hprime1;
            d = c;
            c = b;
            b = a;
            a = hprime1 + hprime2;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    public static byte[] digest(InputStream stream) throws IOException {
        PaddedInputStream ps = new PaddedInputStream(stream);

        int[] state = new int[8];
        int[] words = new int[64];
        initialiseState(state);
        byte[] buffer = new byte[64];
        while (true) {
            int bytesRead = ps.read(buffer);
            if (bytesRead <= 0)
                break;
            int[] messageBlock = bytesToInts(buffer);
            expandWords(messageBlock, words);
            compressionFunction(state, words);
        }
        return intsToBytes(state);
    }

    public static byte[] continueDigest(InputStream stream, byte[] originalState, int originalLength) throws IOException {
        PaddedInputStream ps = new PaddedInputStream(stream, originalLength);

        int[] state = bytesToInts(originalState);
        int[] words = new int[64];
        byte[] buffer = new byte[64];

        while (true) {
            int bytesRead = ps.read(buffer);
            if (bytesRead <= 0)
                break;
            int[] messageBlock = bytesToInts(buffer);
            expandWords(messageBlock, words);
            compressionFunction(state, words);
        }
        return intsToBytes(state);
    }

    // Rotates int x to the right by n bits
    static int rotr(int x, int n) {
        return (x >>> n) | (x << (32 - n));
    }

    // Converts an array of bytes to an array of ints using big endian order
    static int[] bytesToInts(byte[] input) {
        int[] output = new int[input.length / 4];

        for (int i = 0; i < output.length; i++) {
            int inputIndex = i * 4;
            output[i] = (input[inputIndex] << 24) | (input[inputIndex + 1] & 0xFF) << 16 | (input[inputIndex + 2] & 0xFF) << 8
                    | input[inputIndex + 3] & 0xFF;
        }
        return output;
    }

    // Converts an array of ints to an array of bytes in big endian order
    static byte[] intsToBytes(int[] input) {
        byte[] output = new byte[input.length * 4];

        for (int i = 0; i < input.length; i++) {
            int outputIndex = i * 4;
            int a = input[i];

            output[outputIndex + 3] = (byte)a;
            output[outputIndex + 2] = (byte)((a & 0x0000FF00) >> 8);
            output[outputIndex + 1] = (byte)((a & 0x00FF0000) >> 16);
            output[outputIndex] = (byte)((a & 0xFF000000) >> 24);

        }
        return output;
    }

}
