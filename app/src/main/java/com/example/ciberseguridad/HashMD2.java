package com.example.ciberseguridad;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashMD2 {
    public static String md2Hash(long x,String algo) {
        String hexdec = Long.toHexString(x);
        try {
            MessageDigest md = MessageDigest.getInstance(algo);
            byte[] messageDigest = md.digest(hexdec.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashText = no.toString(16);
            while (hashText.length() < 32) {
                hashText = "0" + hashText;
            }
            return hashText;

        }catch(NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
