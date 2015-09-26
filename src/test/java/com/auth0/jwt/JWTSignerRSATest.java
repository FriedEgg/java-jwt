package com.auth0.jwt;

import org.junit.BeforeClass;
import org.junit.Test;

import java.security.*;
import java.util.HashMap;
import org.bouncycastle.util.encoders.Base64;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class JWTSignerRSATest {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static JWTSigner signer;

    @BeforeClass
    public static void onlyOnce() throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        final byte[] seed = JWTSignerRSATest.class.getName().getBytes("UTF-8");
        random.setSeed(seed);
        keyGen.initialize(1024,random);
        final KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        signer = new JWTSigner(privateKey);
    }

    public boolean verify(PublicKey publicKey,String signedData,String signature) {
        Signature sig;
        try {
            sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(signedData.getBytes());
            if (!sig.verify(Base64.decode(signature))) {
                return false;
            }
            return true;
        } catch ( Exception e ) {}
        return false;
    }

    @Test
    public void shouldSignEmpty() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims,new JWTSigner.Options().setAlgorithm(Algorithm.RS256));
        assertNotNull(token);
    }
}
