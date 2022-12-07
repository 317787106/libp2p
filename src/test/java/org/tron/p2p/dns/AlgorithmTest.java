package org.tron.p2p.dns;


import java.math.BigInteger;
import java.security.SignatureException;
import org.junit.Assert;
import org.junit.Test;
import org.tron.p2p.dns.tree.Algorithm;
import org.tron.p2p.utils.ByteArray;

public class AlgorithmTest {

  String privateKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";

  @Test
  public void testPublicKeyCompressAndUnCompress() {
    BigInteger publicKeyInt = Algorithm.generateKeyPair(privateKey).getPublicKey();

    String publicKey = ByteArray.toHexString(publicKeyInt.toByteArray());
    String puKeyCompress = Algorithm.compressPubKey(publicKeyInt);
    String uncompressPubkey = Algorithm.decompressPubKey(puKeyCompress);
    Assert.assertEquals(publicKey, uncompressPubkey);
  }

  @Test
  public void testSignatureAndVerify() {
    BigInteger publicKeyInt = Algorithm.generateKeyPair(privateKey).getPublicKey();
    String publicKey = ByteArray.toHexString(publicKeyInt.toByteArray());

    String msg = "Message for signing";
    byte[] sig = Algorithm.sigData(msg, privateKey);
    try {
      Assert.assertTrue(Algorithm.verifySignature(publicKey, msg, sig));
    } catch (SignatureException e) {
      Assert.fail();
    }
  }

  @Test
  public void testEncode32() {
    String content = "enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org";
    String base32 = Algorithm.encode32(content.getBytes());
    Assert.assertArrayEquals(content.getBytes(), Algorithm.decode32(base32));

    Assert.assertEquals("C7HRFPF3BLGF3YR4DY5KX3SMBE", Algorithm.encode32AndTruncate(content));
  }

  @Test
  public void testValidHash() {
    Assert.assertTrue(Algorithm.isValidHash("C7HRFPF3BLGF3YR4DY5KX3SMBE"));
    Assert.assertFalse(Algorithm.isValidHash("C7HRFPF3BLGF3YR4DY5KX3SMBE======"));
  }

  @Test
  public void testEncode64() {
    String base64Sig = "1eFfi7ggzTbtAldC1pfXPn5A3mZQwEdk0-ZwCKGhZbQn2E6zWodG7v06kFu8gjiCe6FvJo04BYvgKHtPJ5pX5wE=";
    byte[] decoded;
    try {
      decoded = Algorithm.decode64(base64Sig);
      Assert.assertEquals(base64Sig, Algorithm.encode64(decoded));
    } catch (Exception e) {
      Assert.fail();
    }

    String base64Content = "1eFfi7ggzTbtAldC1pfXPn5A3mZQwEdk0-ZwCKGhZbQn2E6zWodG7v06kFu8gjiCe6FvJo04BYvgKHtPJ5pX5wE";
    decoded = Algorithm.decode64(base64Content);
    Assert.assertNotEquals(base64Content, Algorithm.encode64(decoded));
  }

  @Test
  public void testRecoverPubkey() {
    String msg = "enrtree-root:v1 e=VXJIDGQECCIIYNY3GZEJSFSG6U l=FDXN3SN67NA5DKA4J2GOK7BVQI seq=3447";
    byte[] sig = Algorithm.sigData(msg, privateKey);
    Assert.assertEquals(65, sig.length);
    String base64Sig = Algorithm.encode64(sig);
    Assert.assertEquals(
        "sRAWqxdvpzS1UmNP1nt7iLuyiJUJgzvCw-635SLfg7A7OqjkI-bfwD-nYz-wdD5Qb8FwAOke37KgIZ9xTxo7BBs=",
        base64Sig);

    byte[] sigData;
    try {
      sigData = Algorithm.decode64(base64Sig);
      Assert.assertArrayEquals(sig, sigData);
    } catch (Exception e) {
      Assert.fail();
    }

    BigInteger publicKeyInt = Algorithm.generateKeyPair(privateKey).getPublicKey();
    try {
      BigInteger recoverPublicKeyInt = Algorithm.recoverPublicKey(msg, sig);
      Assert.assertEquals(publicKeyInt, recoverPublicKeyInt);
    } catch (SignatureException e) {
      Assert.fail();
    }
  }
}
