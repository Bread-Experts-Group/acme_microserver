package org.bread_experts_group.acme_microserver

import org.bread_experts_group.coder.fixed.json.JSONElement.Companion.json
import org.bread_experts_group.coder.fixed.json.JSONString
import java.io.InputStream
import java.net.URI
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

data class ACMEOrderResponse(
	val status: String,
	val expires: ZonedDateTime,
	val identifiers: List<ACMEIdentifier>,
	val authorizations: List<URI>,
	val finalize: URI,
	val certificate: URI?
) {
	companion object {
		fun read(from: InputStream): ACMEOrderResponse = json(from).asObject {
			ACMEOrderResponse(
				withString("status"),
				ZonedDateTime.from(
					DateTimeFormatter
						.ISO_DATE_TIME
						.parse(withString("expires"))
				),
				inArray("identifiers") {
					it.asObject {
						ACMEIdentifier(
							withString("type"),
							withString("value")
						)
					}
				}.toList(),
				inArray("authorizations") {
					URI(it.asString { value })
				}.toList(),
				URI(withString("finalize")),
				(entries["certificate"] as? JSONString)?.let { URI(it.value) }
			)
		}
	}
}