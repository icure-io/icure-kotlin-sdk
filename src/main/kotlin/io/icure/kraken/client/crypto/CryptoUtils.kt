package io.icure.kraken.client.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.nio.ByteBuffer
import java.security.*
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object CryptoUtils {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    const val IV_BYTE_LENGTH = 16
    val random: SecureRandom = SecureRandom.getInstance("SHA1PRNG")

    fun generateKeyPairRSA(): KeyPair {
        val rsaKeyGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
        return rsaKeyGenerator.generateKeyPair()
    }

    fun encryptRSA(data: ByteArray, publicKey: Key): ByteArray {
        val cipher: Cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "BC")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(data)
    }

    fun decryptRSA(data: ByteArray, privateKey: Key): ByteArray {
        val cipher: Cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "BC")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(data)
    }

    fun encryptAES(data: ByteArray, key: ByteArray): ByteArray {
        val iv = generateIV(IV_BYTE_LENGTH)
        val cipherData = encryptAES(data, key, iv)
        return iv + cipherData
    }

    fun decryptAESWithAnyKey(data: ByteArray, enckeys: List<String>) =
        enckeys.fold(null) { decrypted: ByteArray?, key: String ->  decrypted ?: try { decryptAES(data, ByteBuffer.wrap(ByteArray(16)).also {
            val uuid: UUID = UUID.fromString(key)
            it.putLong(uuid.mostSignificantBits)
            it.putLong(uuid.leastSignificantBits)
        }.array()) } catch (e:Exception) { null } } ?: throw BadPaddingException("Invalid keys")

    fun encryptAESWithAnyKey(data: ByteArray, key: String) = encryptAES(data, ByteBuffer.wrap(ByteArray(16)).also {
        val uuid: UUID = UUID.fromString(key)
        it.putLong(uuid.mostSignificantBits)
        it.putLong(uuid.leastSignificantBits)
    }.array())

    fun decryptAES(data: ByteArray, key: ByteArray): ByteArray {
        val iv: ByteArray = Arrays.copyOf(data, IV_BYTE_LENGTH)
        val encData: ByteArray = Arrays.copyOfRange(data, IV_BYTE_LENGTH, data.size)
        return decryptAES(encData, key, iv)
    }

    fun encryptAES(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher: Cipher =
            Cipher.getInstance("AES/CBC/PKCS7Padding") // js WebCrypto uses PKCS7 as mentioned in the standard.
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), ivSpec)
        return cipher.doFinal(data)
    }

    fun decryptAES(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher: Cipher =
            Cipher.getInstance("AES/CBC/PKCS7Padding") // js WebCrypto uses PKCS7 as mentioned in the standard.
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), ivSpec)
        return cipher.doFinal(data)
    }

    fun generateKeyAES(): Key {
        val aesKeyGenerator: KeyGenerator = KeyGenerator.getInstance("AES", "BC")
        aesKeyGenerator.init(256)
        return aesKeyGenerator.generateKey()
    }

    fun generateIV(ivSize: Int): ByteArray {
        val ivBytes = ByteArray(ivSize)
        random.nextBytes(ivBytes)
        return ivBytes
    }
}

@ExperimentalUnsignedTypes // just to make it clear that the experimental unsigned types are used
fun ByteArray.keyToHexString() = asUByteArray().joinToString("") { it.toString(16).padStart(2, '0') }
fun String.keyFromHexString(): ByteArray {
    this.replace("-","").let {
        check(it.length % 2 == 0) { "Must have an even length" }

        return it.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

    }
}
fun String.toPublicKey() = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyFromHexString())) as RSAPublicKey

fun String.toPrivateKey() = KeyFactory.getInstance("RSA").generatePrivate(
    PKCS8EncodedKeySpec(
        keyFromHexString()
    )) as RSAPrivateKey

@ExperimentalUnsignedTypes
fun KeyPair.publicKeyAsString() = this.public.encoded.keyToHexString()
@ExperimentalUnsignedTypes
fun KeyPair.privateKeyAsString() = this.private.encoded.keyToHexString()
