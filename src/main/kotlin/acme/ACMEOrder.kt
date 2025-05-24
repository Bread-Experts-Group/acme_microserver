package org.bread_experts_group.acme_microserver

import org.bread_experts_group.coder.fixed.json.JSONConvertible

data class ACMEOrder(
	val type: String,
	val value: String
) : JSONConvertible {
	override fun toJSON(): String = buildString {
		append('{')
		append("\"type\":\"$type\",")
		append("\"value\":\"$value\"")
		append('}')
	}
}