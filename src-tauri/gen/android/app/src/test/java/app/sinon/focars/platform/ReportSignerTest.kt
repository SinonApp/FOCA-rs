package app.sinon.focars.platform

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReportSignerTest {
  private fun generateEcP256(): java.security.KeyPair {
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    return kpg.generateKeyPair()
  }

  @Test fun signVerifyAndTamperDetection() {
    val kp = generateEcP256()
    val payload = "{\"schema\":\"foca-custody/v1\",\"report_sha256\":\"abcd\"}".toByteArray()
    val signed = ReportSigner.signWithPrivateKey(payload, kp.private, kp.public.encoded)
    assertEquals(ReportSigner.ALG, signed.alg)
    assertEquals(ReportSigner.ALIAS, signed.keyAlias)
    assertTrue(ReportSigner.verifyDer(payload, signed.signature, signed.publicKeySpki))

    val tampered = payload.clone().also { it[0] = 'X'.code.toByte() }
    assertFalse(ReportSigner.verifyDer(tampered, signed.signature, signed.publicKeySpki))

    val other = generateEcP256()
    assertFalse(ReportSigner.verifyDer(payload, signed.signature, other.public.encoded))
    assertFalse(ReportSigner.verifyDer(payload, byteArrayOf(1, 2, 3), signed.publicKeySpki))
  }

  @Test fun foreignKeySignatureIsValidButNotOwn() {
    val mine = generateEcP256()
    val theirs = generateEcP256()
    val payload = "{\"schema\":\"foca-custody/v1\"}".toByteArray()
    val signed = ReportSigner.signWithPrivateKey(payload, theirs.private, theirs.public.encoded)

    val foreign = ReportSigner.check(payload, signed.signature, theirs.public.encoded, mine.public.encoded)
    assertTrue(foreign.valid)
    assertFalse(foreign.ownKey)
    assertEquals(ReportSigner.fingerprint(theirs.public.encoded), foreign.fingerprint)
    assertEquals(64, foreign.fingerprint!!.length)

    val own = ReportSigner.check(payload, signed.signature, theirs.public.encoded, theirs.public.encoded)
    assertTrue(own.valid && own.ownKey)

    val tampered = payload.clone().also { it[2] = 'X'.code.toByte() }
    val bad = ReportSigner.check(tampered, signed.signature, theirs.public.encoded, mine.public.encoded)
    assertFalse(bad.valid)

    // No embedded key: only the local key is tried, so another device's signature does not verify.
    val noKey = ReportSigner.check(payload, signed.signature, null, mine.public.encoded)
    assertTrue(noKey.ownKey)
    assertFalse(noKey.valid)
  }
}
