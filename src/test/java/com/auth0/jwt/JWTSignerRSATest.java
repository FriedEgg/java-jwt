package com.auth0.jwt;

import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

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

    @Test
    public void shouldSignStringOrURI1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("iss", "foo");
        String token = signer.sign(claims, new JWTSigner.Options().setAlgorithm(Algorithm.RS256));
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJmb28ifQ.QfeJdDu6S-PMgTQiXhRygWFMhy3vhK8rxU6F06TtNqT0t5bKNzBB2kKlRAjxXrGwpGi9fepMxkM5c28UbJQizQ", token);
    }

    @Test
    public void shouldSignStringOrURI2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("sub", "http://foo");
        String token = signer.sign(claims, new JWTSigner.Options().setAlgorithm(Algorithm.RS256));
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJodHRwOi8vZm9vIn0.bERekqQ2o7G-OkolziHuw_1G5Z70GMe7aVwJNoabFfM20Ye1iwIcF9-V6JhJ4_2AS77wq35DFkOIArxrmVwliA", token);
    }

    @Test
    public void shouldSignStringOrURI3() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("aud", "");
        String token = signer.sign(claims, new JWTSigner.Options().setAlgorithm(Algorithm.RS256));
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIifQ.BpP5o2pAmnAImeYBvFsGLoH3mk7W3Uvo-7bx2dwGRkCK0Orbj1H16_8GCOBS3gr3-4VUhJL8LMUwqxDKDiKeTw", token);
    }

    @Test
    public void shouldSignStringOrURICollection() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        LinkedList<String> aud = new LinkedList<String>();
        aud.add("xyz");
        aud.add("ftp://foo");
        claims.put("aud", aud);
        String token = signer.sign(claims, new JWTSigner.Options().setAlgorithm(Algorithm.RS256));
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsieHl6IiwiZnRwOi8vZm9vIl19.UaokqTaxFi_N55fysWk777gkVmr-QaNMOoNwcB1LaGEqNuHUsXWpKz9GRamXtDTxhKM7sntVcoJY6A8JJUvOEA", token);
    }

    @Test
    public void shouldSignIntDate1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("exp", 123);
        String token = signer.sign(claims, new JWTSigner.Options().setAlgorithm(Algorithm.RS256));
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjEyM30.BAIzcmorTNXftKRnFg1IZrLrCP9fPGPiw4VVm1ZzwJv2Loperjow8fAK58l9022uK_jFecE304Yp4YW77_gBoQ", token);
    }

    @Test
    public void shouldSignIntDate2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("nbf", 0);
        String token = signer.sign(claims, new JWTSigner.Options().setAlgorithm(Algorithm.RS256));
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYmYiOjB9.EOdbFJGFnZM8__2qC89DDRHWyn4nu-ZkGubSBoU9hhauYsNpXNTq3GMwn3eR5-lrLqr-I28Ox7rCoS3I6zstqg", token);
    }

    @Test
    public void shouldSignString() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("jti", "foo");
        String token = signer.sign(claims, new JWTSigner.Options().setAlgorithm(Algorithm.RS256));
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJmb28ifQ.J2crfrgWFs7ha3L11lSRkrEtACgtNBKC5LERmieTFz1_o0jCTK1XSkhI6wZvXIhNUmH2U34k30zqFsNNdJ13JA", token);
    }

    @Test
    public void shouldSignNullEqualsMissing() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        for (String claimName : Arrays.asList("iss", "sub", "aud", "exp", "nbf", "iat", "jti")) {
            claims.put(claimName, null);
        }
        String token = signer.sign(claims, new JWTSigner.Options().setAlgorithm(Algorithm.RS256));
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.e30.qL1rltWgwbxh1DXOGfehekZXPqZIgVaeOMc2Rd5wpHCH4ewlMCyw0fN32nj230RNDwB8Hj8ns6Nhwc6V8qWHpQ", token);
    }

}
