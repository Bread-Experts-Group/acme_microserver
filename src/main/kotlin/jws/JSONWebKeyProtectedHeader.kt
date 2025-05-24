package org.bread_experts_group.acme_microserver.jws

import org.bread_experts_group.coder.fixed.json.JSONConvertible
import java.net.URI

@ConsistentCopyVisibility
data class JSONWebKeyProtectedHeader private constructor(
	val algorithm: String,
	val nonce: String,
	val url: URI,
	val jsonWebKey: JSONWebKey?,
	val keyID: String?
) : JSONConvertible {
	constructor(
		algorithm: String,
		nonce: String,
		url: URI,
		jsonWebKey: JSONWebKey
	) : this(algorithm, nonce, url, jsonWebKey, null)

	constructor(
		algorithm: String,
		nonce: String,
		url: URI,
		keyID: String
	) : this(algorithm, nonce, url, null, keyID)

	override fun toJSON(): String = buildString {
		append('{')
		append("\"alg\":\"$algorithm\",")
		if (jsonWebKey != null) append("\"jwk\":${jsonWebKey.toJSON()},")
		if (keyID != null) append("\"kid\":\"$keyID\",")
		append("\"nonce\":\"$nonce\",")
		append("\"url\":\"$url\"")
		append('}')
	}
}