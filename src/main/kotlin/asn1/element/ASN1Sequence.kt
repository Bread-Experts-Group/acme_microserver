package org.bread_experts_group.acme_microserver.asn1.element

import java.io.ByteArrayOutputStream
import java.io.OutputStream

data class ASN1Sequence(
	val elements: List<ASN1Element>
) : ASN1Element(48, byteArrayOf()) {
	constructor(
		vararg elements: ASN1Element
	) : this(listOf(*elements))

	override fun toString(): String = "ASN1Sequence[${elements.size}]$elements"

	override fun writeExtra(stream: OutputStream) {
		val buffer = ByteArrayOutputStream(elements.size * 2)
		elements.forEach {
			it.write(buffer)
		}
		stream.writeLength(buffer.size())
		stream.write(buffer.toByteArray())
	}
}