package org.bread_experts_group.acme_microserver.asn1.element

import java.io.OutputStream

data class ASN1Boolean(
	val value: Boolean
) : ASN1Element(1, byteArrayOf()) {
	override fun writeExtra(stream: OutputStream) {
		stream.writeLength(1)
		stream.write(if (value) 0xFF else 0)
	}
}