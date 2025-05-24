package org.bread_experts_group.acme_microserver.asn1.element

import org.bread_experts_group.stream.writeString
import java.io.OutputStream

data class ASN1UTFString(
	val string: String
) : ASN1Element(12, byteArrayOf()) {
	override fun writeExtra(stream: OutputStream) {
		stream.writeLength(string.length)
		stream.writeString(string)
	}
}