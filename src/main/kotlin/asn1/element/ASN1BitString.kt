package org.bread_experts_group.acme_microserver.asn1.element

import java.io.OutputStream

data class ASN1BitString(
	val string: ByteArray
) : ASN1Element(3, byteArrayOf()) {
	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (javaClass != other?.javaClass) return false

		other as ASN1BitString

		return string.contentEquals(other.string)
	}

	override fun hashCode(): Int {
		return string.contentHashCode()
	}

	override fun writeExtra(stream: OutputStream) {
		stream.writeLength(string.size + 1)
		stream.write(0)
		stream.write(string)
	}
}