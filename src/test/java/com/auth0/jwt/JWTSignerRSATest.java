package com.auth0.jwt;

import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;

public class JWTSignerRSATest {
    private static JWTSigner signer;

    @BeforeClass
    public static void onlyOnce() throws Exception {
        BigInteger modulus = new BigInteger("AB34D0D48B16438BBBDFF6DA0CC7D3936DC2CE71E89DEF5B4AA9EA2539EAC17B5765FAAF2C533D176AF95CF16F157FECB977F51DE6E5473808E95A487321A3AB", 16);
        BigInteger privateExponent = new BigInteger("0FEA1CEF64EE70E0F059E54C679BBBA31CB4DB13E397AAC445B07DBF701ECE554DE0266E99B96CE8F3148291551E70357E5AF29FB192FB9E5C2F4AA5C45A0141", 16);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus,privateExponent);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(rsaPrivateKeySpec);

        signer = new JWTSigner(rsaPrivateKey);
    }

    @Test
    public void shouldSignEmpty() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims, new JWTSigner.Options().setAlgorithm(Algorithm.RS256));
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.e30.qL1rltWgwbxh1DXOGfehekZXPqZIgVaeOMc2Rd5wpHCH4ewlMCyw0fN32nj230RNDwB8Hj8ns6Nhwc6V8qWHpQ",token);
    }
}
