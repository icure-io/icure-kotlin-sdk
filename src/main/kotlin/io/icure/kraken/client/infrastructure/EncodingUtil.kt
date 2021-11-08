package io.icure.kraken.client.infrastructure

import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.net.URLEncoder


/**
 * Utility class for JavaScript compatible UTF-8 encoding and decoding.
 *
 * @see http://stackoverflow.com/questions/607176/java-equivalent-to-javascripts-encodeuricomponent-that-produces-identical-output
 *
 * @author John Topley
 */
object EncodingUtil {
    /**
     * Decodes the passed UTF-8 String using an algorithm that's compatible with
     * JavaScript's `decodeURIComponent` function. Returns
     * `null` if the String is `null`.
     *
     * @param s The UTF-8 encoded String to be decoded
     * @return the decoded String
     */
    fun decodeURIComponent(s: String?): String? {
        if (s == null) {
            return null
        }
        var result: String? = null
        result = try {
            URLDecoder.decode(s, "UTF-8")
        } // This exception should never occur.
        catch (e: UnsupportedEncodingException) {
            s
        }
        return result
    }

    /**
     * Encodes the passed String as UTF-8 using an algorithm that's compatible
     * with JavaScript's `encodeURIComponent` function. Returns
     * `null` if the String is `null`.
     *
     * @param s The String to be encoded
     * @return the encoded String
     */
    fun encodeURIComponent(s: String?): String? {
        var result: String? = null
        result = try {
            URLEncoder.encode(s, "UTF-8")
                .replace("\\+".toRegex(), "%20")
                .replace("\\%21".toRegex(), "!")
                .replace("\\%27".toRegex(), "'")
                .replace("\\%28".toRegex(), "(")
                .replace("\\%29".toRegex(), ")")
                .replace("\\%7E".toRegex(), "~")
        } // This exception should never occur.
        catch (e: UnsupportedEncodingException) {
            s
        }
        return result
    }
}
