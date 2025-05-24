package org.bread_experts_group.acme_microserver.asn1

import org.bread_experts_group.acme_microserver.asn1.element.ASN1BitString
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Element
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Integer
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Null
import org.bread_experts_group.acme_microserver.asn1.element.ASN1ObjectIdentifier
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Sequence
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Boolean
import org.bread_experts_group.acme_microserver.asn1.element.ASN1OctetString
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Set
import org.bread_experts_group.coder.format.Parser
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.math.BigInteger

class ASN1InputStream(from: InputStream) : Parser<Int, ASN1Element>("Abstract Syntax Notation One", from) {
	override fun readParsed(): ASN1Element {
		val element = ASN1Element(
			this.read(),
			this.readNBytes(this.read())
		)
		val parser = this.parsers[element.tag]
		this.logger.fine {
			"Read generic element [${element.tag}], size [${element.data.size}]" +
					if (parser != null) " | responsible parser: $parser"
					else ""
		}
		return parser?.invoke(ByteArrayInputStream(element.data))?.also {
			this.logger.fine { "Parsed element into [${it.javaClass.canonicalName}] from [$parser], $element" }
		} ?: element
	}

	init {
		addParser(1) { ASN1Boolean(it.read() == 0xFF) }
		addParser(2) { ASN1Integer(BigInteger(it.readAllBytes())) }
		addParser(3) { ASN1BitString(it.readAllBytes()) }
		addParser(4) { ASN1OctetString(it.readAllBytes()) }
		addParser(5) { ASN1Null() }
		addParser(6) {
			ASN1ObjectIdentifier(
				buildList {
					val firstByte = it.read()
					add(firstByte / 40)
					add(firstByte % 40)

					var value = 0
					while (true) {
						val b = it.read()
						if (b == -1) break
						value = (value shl 7) or (b and 0x7F)
						if ((b and 0x80) == 0) {
							add(value)
							value = 0
						}
					}
				}.toTypedArray()
			)
		}
		addParser(16) { ASN1Set(ASN1InputStream(it).readAllParsed()) }
		addParser(17) { ASN1Sequence(ASN1InputStream(it).readAllParsed()) }
		addParser(48) { ASN1Sequence(ASN1InputStream(it).readAllParsed()) }
	}
}