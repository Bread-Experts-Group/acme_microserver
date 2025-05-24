package org.bread_experts_group.acme_microserver.jws

import org.bread_experts_group.acme_microserver.crypto.KeyPairFile
import org.bread_experts_group.acme_microserver.crypto.read
import org.bread_experts_group.coder.fixed.json.JSONConvertible
import java.math.BigInteger
import java.security.KeyPair
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.util.*


data class JSONWebKey(
	val keyType: String,
	val curve: String,
	val x: String,
	val y: String
) : JSONConvertible {
	override fun toJSON(): String = buildString {
		append('{')
		append("\"kty\":\"$keyType\",")
		append("\"crv\":\"$curve\",")
		append("\"x\":\"$x\",")
		append("\"y\":\"$y\"")
		append('}')
	}

	fun thumbprint(): String {
		val canonicalJson = """{"crv":"$curve","kty":"$keyType","x":"$x","y":"$y"}"""
		val md = MessageDigest.getInstance("SHA-256")
		val hash = md.digest(canonicalJson.toByteArray(Charsets.UTF_8))
		return Base64.getUrlEncoder().withoutPadding().encode(hash).decodeToString()
	}

	companion object {
		fun BigInteger.to32Bytes(): ByteArray {
			val full = this.toByteArray()
			return when {
				full.size == 32 -> full
				full.size < 32 -> ByteArray(32 - full.size) + full
				full.size == 33 && full[0] == 0.toByte() -> full.copyOfRange(1, 33)
				else -> throw IllegalArgumentException("Invalid size for r or s")
			}
		}

		fun BigInteger.to48Bytes(): ByteArray {
			val full = this.toByteArray()
			return when {
				full.size == 48 -> full
				full.size < 48 -> ByteArray(48 - full.size) + full
				full.size == 49 && full[0] == 0.toByte() -> full.copyOfRange(1, 49)
				else -> throw IllegalArgumentException("Invalid size for r or s")
			}
		}

		fun newEclipticCurveJWT(
			pair: KeyPairFile? = null
		): Pair<JSONWebKey, KeyPair> {
			val keyPair = pair.read()
			val (x, y) = Base64.getUrlEncoder().withoutPadding().let {
				val ecPublicKey = keyPair.public as ECPublicKey
				val x = it.encodeToString(ecPublicKey.w.affineX.to32Bytes())
				val y = it.encodeToString(ecPublicKey.w.affineY.to32Bytes())
				x to y
			}
			return JSONWebKey(
				"EC", "P-256",
				x, y
			) to keyPair
		}
	}
}
