package org.bread_experts_group.acme_microserver.asn1.element

import java.io.ByteArrayOutputStream
import java.io.OutputStream

data class ASN1ObjectIdentifier(
	val values: Array<Int>
) : ASN1Element(6, byteArrayOf()) {
	constructor(
		vararg values: Int
	) : this(values.toTypedArray())

	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (javaClass != other?.javaClass) return false

		other as ASN1ObjectIdentifier

		return values.contentEquals(other.values)
	}

	override fun hashCode(): Int {
		return values.contentHashCode()
	}

	override fun writeExtra(stream: OutputStream) {
		require(values.size >= 2) { "OID must have at least two components" }

		val body = ByteArrayOutputStream()

		// Encode the first byte
		val first = 40 * values[0] + values[1]
		body.write(first)

		// Encode remaining components
		for (i in 2 until values.size) {
			encodeBase128(values[i], body)
		}

		// Now write the length prefix
		val encoded = body.toByteArray()
		stream.writeLength(encoded.size)
		stream.write(encoded)
	}

	// Encodes a single integer using base-128 with MSB continuation bit
	private fun encodeBase128(value: Int, stream: OutputStream) {
		var v = value
		val stack = mutableListOf<Byte>()

		do {
			stack.add((v and 0x7F).toByte())
			v = v ushr 7
		} while (v > 0)

		// Write in reverse order, MSB=1 for all but last
		for (i in stack.indices.reversed()) {
			val byte = stack[i]
			if (i != 0) stream.write(byte.toInt() or 0x80)
			else stream.write(byte.toInt())
		}
	}
}