package org.bread_experts_group.acme_microserver.asn1.element

import org.bread_experts_group.stream.writeString
import java.io.OutputStream
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

data class ASN1UTCTime private constructor(
	val time: String
) : ASN1Element(23, byteArrayOf()) {
	constructor(
		time: ZonedDateTime
	) : this(
		DateTimeFormatter.ofPattern("yyMMddHHmmssxx")
			.format(time)
	)

	override fun writeExtra(stream: OutputStream) {
		stream.writeLength(time.length)
		stream.writeString(time)
	}
}