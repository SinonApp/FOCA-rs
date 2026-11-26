package app.sinon.focars.platform

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.tauri.plugin.JSObject
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/**
 * Hardware-backed report signing and verification via AndroidKeyStore ECDSA P-256 (`secp256r1`).
 * Keys never leave the Keystore boundary; the detached X.509 SPKI public key is exported in
 * `.sig.json` so auditors can verify custody manifests independently.
 */
object ReportSigner {
  const val ALIAS = "focars_report_sign_p256"
  const val ALG = "ECDSA-P256-SHA256"
  private const val ANDROID_KEYSTORE = "AndroidKeyStore"
  private const val JCA_SIGN_ALG = "SHA256withECDSA"

  data class SignedBytes(
    val alg: String,
    val keyAlias: String,
    val signature: ByteArray,
    val publicKeySpki: ByteArray,
  )

  fun signWithPrivateKey(
    payload: ByteArray,
    privateKey: PrivateKey,
    publicKeySpki: ByteArray,
    keyAlias: String = ALIAS,
  ): SignedBytes {
    val sig = Signature.getInstance(JCA_SIGN_ALG)
    sig.initSign(privateKey)
    sig.update(payload)
    return SignedBytes(
      alg = ALG,
      keyAlias = keyAlias,
      signature = sig.sign(),
      publicKeySpki = publicKeySpki,
    )
  }

  fun verifyDer(payload: ByteArray, sigDer: ByteArray, publicKeySpki: ByteArray): Boolean = try {
    val kf = KeyFactory.getInstance("EC")
    val pub = kf.generatePublic(X509EncodedKeySpec(publicKeySpki))
    val sig = Signature.getInstance(JCA_SIGN_ALG)
    sig.initVerify(pub)
    sig.update(payload)
    sig.verify(sigDer)
  } catch (_: Throwable) {
    false
  }

  /**
   * Outcome of checking a signature: [ownKey] when the embedded key (or no key at all) is this
   * device's key, [valid] when the signature matches the payload under the embedded/own key.
   */
  data class Check(val valid: Boolean, val ownKey: Boolean, val fingerprint: String?)

  /** SHA-256 of the SPKI public key, lowercase hex (shown to the user to compare keys). */
  fun fingerprint(spki: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(spki).joinToString("") { "%02x".format(it) }

  /**
   * Pure verification policy: a report signed on another device embeds that device's public key, so
   * a valid signature under a foreign key is reported as valid-but-foreign rather than invalid.
   * Without an embedded key only the local key can be used.
   */
  fun check(payload: ByteArray, sigDer: ByteArray, embeddedSpki: ByteArray?, localSpki: ByteArray?): Check {
    val embedded = embeddedSpki?.takeIf { it.isNotEmpty() }
    val own = localSpki != null && (embedded == null || MessageDigest.isEqual(embedded, localSpki))
    val key = if (own) localSpki else embedded
    val valid = key != null && verifyDer(payload, sigDer, key)
    return Check(valid, own, key?.let { fingerprint(it) })
  }

  private val keyLock = Any()

  private fun getOrCreateKeyPair(): KeyPair = synchronized(keyLock) {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
    ks.load(null)
    val entry = ks.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry
    if (entry != null) {
      return@synchronized KeyPair(entry.certificate.publicKey, entry.privateKey)
    }
    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
    val spec = KeyGenParameterSpec.Builder(
      ALIAS,
      KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
    )
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
      .setDigests(KeyProperties.DIGEST_SHA256)
      .build()
    kpg.initialize(spec)
    return@synchronized kpg.generateKeyPair()
  }

  private fun currentPublicKeySpki(): ByteArray? = synchronized(keyLock) {
    try {
      val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
      ks.load(null)
      ks.getCertificate(ALIAS)?.publicKey?.encoded
    } catch (_: Throwable) {
      null
    }
  }

  fun call(cmd: String, a: JSObject): JSObject = when (cmd) {
    "report_sign" -> {
      val payloadB64 = a.getString("payload_b64", null) ?: ""
      val payload = Base64.decode(payloadB64, Base64.DEFAULT)
      val kp = getOrCreateKeyPair()
      val signed = signWithPrivateKey(payload, kp.private, kp.public.encoded)
      JSObject()
        .put("ok", true)
        .put("alg", signed.alg)
        .put("key_alias", signed.keyAlias)
        .put("sig_b64", Base64.encodeToString(signed.signature, Base64.NO_WRAP))
        .put("pubkey_b64", Base64.encodeToString(signed.publicKeySpki, Base64.NO_WRAP))
    }
    "report_sig_verify" -> {
      val payload = Base64.decode(a.getString("payload_b64", null) ?: "", Base64.DEFAULT)
      val sigDer = Base64.decode(a.getString("sig_b64", null) ?: "", Base64.DEFAULT)
      val localPub = currentPublicKeySpki()
      val embedded = a.getString("pubkey_b64", null)?.takeIf { it.isNotBlank() }?.let {
        try { Base64.decode(it, Base64.DEFAULT) } catch (_: Throwable) { ByteArray(0) }
      }
      // An undecodable embedded key must not fall back to the local key.
      val c = if (embedded != null && embedded.isEmpty()) Check(false, false, null)
        else check(payload, sigDer, embedded, localPub)
      // `valid` keeps its meaning (own key) for older cores; `foreign_valid` covers other devices.
      JSObject()
        .put("ok", true)
        .put("valid", c.valid && c.ownKey)
        .put("foreign_valid", c.valid && !c.ownKey)
        .put("own_key", c.ownKey)
        .put("key_fp", c.fingerprint ?: "")
    }
    else -> JSObject().put("error", "unknown: $cmd")
  }
}
