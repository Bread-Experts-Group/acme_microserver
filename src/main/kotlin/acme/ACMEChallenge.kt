package org.bread_experts_group.acme_microserver

import org.bread_experts_group.coder.fixed.json.JSONElement.Companion.json
import java.io.InputStream
import java.net.URI

data class ACMEChallenge(
	val type: String,
	val url: URI,
	val status: String,
	val token: String
) {
	companion object {
		fun read(stream: InputStream): ACMEChallenge = json(stream).asObject {
			ACMEChallenge(
				withString("type"),
				URI(withString("url")),
				withString("status"),
				withString("token")
			)
		}
	}
}