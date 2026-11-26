package app.sinon.focars.platform

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * API key storage (the engine's `KeyProvider`): AES-256-GCM with the key in AndroidKeyStore
 * (StrongBox when available) and the ciphertext in private SharedPreferences. The service name is
 * the AAD, so one service's entry cannot be swapped in for another. Not bound to device unlock,
 * because scans read keys in the background. `allowBackup=false` in the manifest keeps the prefs
 * file out of cloud backups, and the Keystore key is not exportable anyway.
 */
class KeyVault(ctx: Context) {
  private val prefs: SharedPreferences =
    ctx.applicationContext.getSharedPreferences("foca_keys", Context.MODE_PRIVATE)

  companion object {
    private const val ALIAS = "foca_api_keys_v1"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private val lock = Any()
  }

  private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

  private fun key(): SecretKey = synchronized(lock) {
    (keyStore().getKey(ALIAS, null) as? SecretKey)?.let { return@synchronized it }
    fun gen(strongBox: Boolean): SecretKey {
      val b = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setRandomizedEncryptionRequired(true)
      if (strongBox && Build.VERSION.SDK_INT >= 28) b.setIsStrongBoxBacked(true)
      val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
      g.init(b.build())
      return g.generateKey()
    }
    return@synchronized if (Build.VERSION.SDK_INT >= 28) {
      try { gen(true) } catch (e: StrongBoxUnavailableException) { gen(false) } catch (e: Exception) { gen(false) }
    } else gen(false)
  }

  fun put(service: String, value: String) = synchronized(lock) {
    val c = Cipher.getInstance(TRANSFORM)
    c.init(Cipher.ENCRYPT_MODE, key())
    c.updateAAD(service.toByteArray(Charsets.UTF_8))
    val ct = c.doFinal(value.toByteArray(Charsets.UTF_8))
    if (!prefs.edit().putString(Codec.prefKey(service), Codec.pack(c.iv, ct)).commit()) {
      throw IllegalStateException("не удалось записать ключ")
    }
  }

  /** Returns the value, or `null` if there is no entry (a corrupted entry or a lost Keystore key deletes it). */
  fun get(service: String): String? = synchronized(lock) {
    val (iv, ct) = Codec.unpack(prefs.getString(Codec.prefKey(service), null)) ?: return@synchronized null
    return@synchronized try {
      val c = Cipher.getInstance(TRANSFORM)
      c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
      c.updateAAD(service.toByteArray(Charsets.UTF_8))
      String(c.doFinal(ct), Charsets.UTF_8)
    } catch (e: KeyPermanentlyInvalidatedException) {
      delete(service); null
    } catch (e: AEADBadTagException) {
      delete(service); null
    }
  }

  fun delete(service: String) {
    synchronized(lock) {
      prefs.edit().remove(Codec.prefKey(service)).commit()
    }
  }
}
