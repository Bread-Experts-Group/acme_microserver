package org.bread_experts_group.acme_microserver.jws

import org.bread_experts_group.acme_microserver.jws.JSONWebKey.Companion.to32Bytes
import org.bread_experts_group.acme_microserver.asn1.ASN1InputStream
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Integer
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Sequence
import org.bread_experts_group.coder.fixed.json.JSONConvertible
import java.io.ByteArrayInputStream
import java.security.KeyPair
import java.security.Signature
import java.util.Base64

data class JSONWebSignatureSignedData(
	val protected: String,
	val payload: String,
	val signature: String
) : JSONConvertible {
	override fun toJSON(): String = buildString {
		append('{')
		append("\"protected\":\"$protected\",")
		append("\"signature\":\"$signature\",")
		append("\"payload\":\"$payload\"")
		append('}')
	}

	companion object {
		fun createSignedData(
			protected: JSONWebKeyProtectedHeader,
			payload: JSONConvertible,
			keyPair: KeyPair
		): JSONWebSignatureSignedData {
			val encoder = Base64.getUrlEncoder().withoutPadding()
			val protectedB64 = encoder.encodeToString(protected.toJSON().toByteArray())
			val payloadB64 = encoder.encodeToString(payload.toJSON().toByteArray())
			val signatureB64 = Signature.getInstance("SHA256withECDSA").let {
				it.initSign(keyPair.private)
				it.update("$protectedB64.$payloadB64".toByteArray())
				val seq = ASN1InputStream(ByteArrayInputStream(it.sign())).readAllParsed()
					.first() as ASN1Sequence
				encoder.encodeToString(
					((seq.elements[0] as ASN1Integer).value).to32Bytes() +
							((seq.elements[1] as ASN1Integer).value).to32Bytes()
				)
			}
			return JSONWebSignatureSignedData(
				protectedB64,
				payloadB64,
				signatureB64
			)
		}
	}
}