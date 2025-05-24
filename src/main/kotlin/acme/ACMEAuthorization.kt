package org.bread_experts_group.acme_microserver

import org.bread_experts_group.coder.fixed.json.JSONElement.Companion.json
import java.io.InputStream
import java.net.URI
import java.time.format.DateTimeFormatter
import java.time.temporal.TemporalAccessor

data class ACMEAuthorization(
	val identifier: ACMEIdentifier,
	val status: String,
	val expires: TemporalAccessor,
	val challenges: List<ACMEChallenge>
) {
	companion object {
		fun read(stream: InputStream): ACMEAuthorization = json(stream).asObject {
			ACMEAuthorization(
				inObject("identifier") {
					ACMEIdentifier(
						withString("type"),
						withString("value")
					)
				},
				withString("status"),
				DateTimeFormatter.ISO_DATE_TIME.parse(withString("expires")),
				inArray("challenges") {
					it.asObject {
						ACMEChallenge(
							withString("type"),
							URI(withString("url")),
							withString("status"),
							withString("token")
						)
					}
				}.toList()
			)
		}
	}
}