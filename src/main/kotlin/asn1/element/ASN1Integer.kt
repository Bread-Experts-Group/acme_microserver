package org.bread_experts_group.acme_microserver.asn1.element

import java.io.OutputStream
import java.math.BigInteger

data class ASN1Integer(
	val value: BigInteger
) : ASN1Element(2, byteArrayOf()) {
	constructor(value: Long) : this(BigInteger.valueOf(value))

	override fun writeExtra(stream: OutputStream) {
		val array = value.toByteArray()
		stream.writeLength(array.size)
		stream.write(array)
	}
}