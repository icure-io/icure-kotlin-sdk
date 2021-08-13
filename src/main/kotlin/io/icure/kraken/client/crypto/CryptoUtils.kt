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
import kotlin.experimental.and

object CryptoUtils {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    const val IV_BYTE_LENGTH = 16
    val random: SecureRandom = SecureRandom.getInstance("SHA1PRNG")

    /**
     * Decodes a hex string to a byte array. The hex string can contain either upper
     * case or lower case letters.
     *
     * @param value string to be decoded
     * @return decoded byte array
     * @throws NumberFormatException If the string contains an odd number of characters
     * or if the characters are not valid hexadecimal values.
     */
    fun decodeHex(value: String): ByteArray {
        // if string length is odd then throw exception
        if (value.length % 2 != 0) {
            throw NumberFormatException("odd number of characters in hex string")
        }
        val bytes = ByteArray(value.length / 2)
        var i = 0
        while (i < value.length) {
            bytes[i / 2] = value.substring(i, i + 2).toInt(16).toByte()
            i += 2
        }
        return bytes
    }

    /**
     * Produces a Writable that writes the hex encoding of the byte[]. Calling
     * toString() on this Writable returns the hex encoding as a String. The hex
     * encoding includes two characters for each byte and all letters are lower case.
     *
     * @param data byte array to be encoded
     * @return object which will write the hex encoding of the byte array
     * @see Integer.toHexString
     */
    var hexArray = "0123456789ABCDEF".toCharArray()
    fun encodeHex(data: ByteArray): String {
        val hexChars = CharArray(data.size * 2)
        for (j in data.indices) {
            val v: Int = (data[j] and (0xFF).toByte()).toInt()
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
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

    fun toPublicKey(publicKeyStr: String) = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(decodeHex(publicKeyStr))) as RSAPublicKey

    fun toPrivateKey(privateKeyStr: String) = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(decodeHex(privateKeyStr))) as RSAPrivateKey
}
