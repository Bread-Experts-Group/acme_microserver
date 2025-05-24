package org.bread_experts_group.acme_microserver.asn1.element

import java.io.OutputStream

class ASN1Tagged(
	tagNumber: Int,
	private val constructed: Boolean,
	val element: ASN1Element
) : ASN1Element((if (constructed) 0xA0 else 0x80) + tagNumber, byteArrayOf()) {
	override fun writeExtra(stream: OutputStream) {
		val inner = element.asBytes()
		if (!constructed) {
			stream.writeLength(inner.size - 2)
			stream.write(inner.sliceArray(2 until inner.size))
		} else {
			stream.writeLength(inner.size)
			stream.write(inner)
		}
	}
}