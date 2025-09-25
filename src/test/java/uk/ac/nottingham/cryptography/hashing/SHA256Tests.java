package uk.ac.nottingham.cryptography.hashing;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SHA256Tests {

    @Test
    void initialiseStateTest() {
        int[] state = new int[8];

        SHA256.initialiseState(state);

        int[] expectedOutput = hexToInts("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19");

        assertArrayEquals(expectedOutput, state);
    }

    @Test
    void expandWordTest() {
        int[] messageBlock1 = new int[16];
        messageBlock1[0] = (1 << 31);
        int[] words = new int[64];
        String output1 = "8000000000000000000000000000000000000000000000000000000000000000" +
                         "0000000000000000000000000000000000000000000000000000000000000000" +
                         "8000000000000000002050000000000022000800000000000508954280000000" +
                         "580800000040a0000016250566001800d622258014225508d645f95cc9282000" +
                         "c3f10094284ca76606886dc6a37bf116717cbe96fec2d74aa7b67f00811596a2" +
                         "98a6e76803b20c825d1da7c9b156b935c3ddca11249c107fc48d24ef5de54c30" +
                         "defece652ca1480d3c15332c01cec9ad160cccd00bacda98361b8fe0d2320ba6" +
                         "029b70077546587c07f54f39f808ddc3dcca76085e42718844bcec5d3b5ec49b";
        SHA256.expandWords(messageBlock1, words);
        assertEquals(output1, intsToHex(words));

        int[] messageBlock2 = new int[16];
        for (int i = 0; i < 16; i++) {
            messageBlock2[i] = Math.floorMod((long)Math.pow(5,i), Integer.MAX_VALUE);
        }
        String output2 = "0000000100000005000000190000007d0000027100000c3500003d090001312d" +
                         "0005f5e1001dcd65009502f902e90edd0e8d4a5148c273956bcc41eb1afd499b" +
                         "b2f138f540939474b851226da9ce17d66725370e524a88566ec8212687a0d146" +
                         "0ea0953bddc73561fc8c1cecd792dafeae192e1cb974b4950d5fecd4a99abf62" +
                         "a23a84d7ca7900cee05d9e0c561cdd6ba292376d9e04cbf81f819c807907c432" +
                         "ec4ca21799f9aa4669fdddecc18b302db2e8d270299dcc61797b6f170fd50524" +
                         "db939cecb8f482f54afb58251cdc104663376e2b069c6d4924fd1b192a7c5bb9" +
                         "c8c50f152e2d8c4b3ced5a72600eff5874766ae9e9126c95a4d85d5a7a7a83a9";
        SHA256.expandWords(messageBlock2, words);
        assertEquals(output2, intsToHex(words));

        int[] messageBlock3 = new int[16];
        for (int i = 0; i < 16; i++) {
            messageBlock3[i] = 0b1011101101 << (i * 2);
        }
        String output3 = "000002ed00000bb400002ed00000bb400002ed00000bb400002ed00000bb4000" +
                         "02ed00000bb400002ed00000bb400000ed000000b4000000d000000040000000" +
                         "76d5764eda94393b800385db43cd46d0537affca8fb41679304dac1b41b94c32" +
                         "4266116c20ce38475347269b065882fa0c26557b5111b5e2fa4b4a343e63d1c3" +
                         "c6af79430728578fd35e5bd59266848772a8c30c7866e6532865667f0cf9ae91" +
                         "6dd264adcc2eebf338ff3bb884781f3aa32ae20f2a02ea55aa745a1015a927dc" +
                         "4447de2c1e70788928e32f6b8f56eccb9f674626717e5077d221599a01b548e9" +
                         "58ef0bdabbfc005b8f1fd7f257889c303b4f163d7c4e506c096affe2f8483b58";
        SHA256.expandWords(messageBlock3, words);
        assertEquals(output3, intsToHex(words));
    }

    @Test
    void compressionFunctionTests() {
        int[] words = new int[64];
        for (int i = 0; i < 64; i++) {
            words[i] = (i * 10) + i;
        }

        int[][] inputs = new int[][] {
                hexToInts("7a03b3bac3a6044c1c6c4313ce3ddef8bf17a2e97cb90e8c9918f42313c7621c"),
                hexToInts("5844074fee80bdc017632820c56806725938bdcc7e96581b63b7feaf0a4666cb"),
                hexToInts("ce171c5b4e542cfaa900bdb06071f3de35931cfa8f4ce9b70db2446790919ad3"),
                hexToInts("b2405012f250bc7d2a31e061f296d3ba6e320ccc8f510faaad58bde103df782e"),
                hexToInts("bc4e06dfccc1e315bdd66638c65a0ded629c3414eb22714c24be3f255f3c7c1e")
        };

        int[][] outputs = new int[][] {
                hexToInts("a54eb0371e124e22b7ec61e25438b90047967831f9a1d369473e41914570dc45"),
                hexToInts("090fea019b0d5e0535c177bed986a2877c07bd44c0c248d17516c459ba94cae5"),
                hexToInts("e973b9e87881a4a8cf4043074d1417fc24108ed9bc3e0290de843624cef39a9b"),
                hexToInts("46681c092397df5365cdfa0598fee79e65b18b4228d86750a7fae03e2c1d93c9"),
                hexToInts("0bb5f698f3f2b88a44d7b0c950a1fb1259cd68411f04c43f760ee5134e9e4efc")
        };

        for (int i = 0; i < 5; i++) {
            int[] input = Arrays.copyOf(inputs[i], 8);
            int[] output = outputs[i];
            SHA256.compressionFunction(input, words);
            assertArrayEquals(output, input);
        }
    }

    @Test
    void sha256Tests() throws IOException {
        // NIST Test vectors
        byte[] a = new byte[1000000];
        Arrays.fill(a, (byte)0b01100001);

        byte[][] inputs = new byte[][] {
                new byte[0],
                "abc".getBytes(),
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(),
                a,
        };
        
        byte[][] outputs = new byte[][] {
                hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                hexToBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                hexToBytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
                hexToBytes("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        };

        for (int i = 0; i < inputs.length; i++) {
            ByteArrayInputStream bs = new ByteArrayInputStream(inputs[i]);
            byte[] output = SHA256.digest(bs);
            assertArrayEquals(outputs[i], output);
        }
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static int[] hexToInts(String s) {
        int len = s.length();
        int[] data = new int[len / 8];
        for (int i = 0; i < len; i += 8) {
            String c = s.substring(i, i+8);
            data[i/8] = (int)Long.parseLong(c, 16);
        }
        return data;
    }

    private static String intsToHex(int[] ints) {
        StringBuilder sb = new StringBuilder();
        for (int i : ints) {
            sb.append(String.format("%8s", Integer.toHexString(i)).replace(" ","0"));
        }
        return sb.toString();
    }

}