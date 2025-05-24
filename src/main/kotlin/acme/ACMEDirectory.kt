package org.bread_experts_group.acme_microserver

import org.bread_experts_group.coder.fixed.json.JSONElement.Companion.json
import java.io.InputStream
import java.net.URI

data class ACMEDirectory(
	val newNonce: URI,
	val newAccount: URI,
	val newOrder: URI,
	val revokeCert: URI
) {
	companion object {
		fun read(from: InputStream): ACMEDirectory = json(from).asObject {
			ACMEDirectory(
				URI(withString("newNonce")),
				URI(withString("newAccount")),
				URI(withString("newOrder")),
				URI(withString("revokeCert"))
			)
		}
	}
}