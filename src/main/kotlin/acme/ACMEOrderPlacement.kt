package org.bread_experts_group.acme_microserver

import org.bread_experts_group.coder.fixed.json.JSONConvertible

data class ACMEOrderPlacement(
	val identifiers: List<ACMEOrder>,
	val profile: String?
) : JSONConvertible {
	override fun toJSON(): String = buildString {
		append('{')
		append("\"identifiers\":[${identifiers.joinToString(",") { it.toJSON() }}]")
		if (profile != null) append(",\"profile\":\"$profile\"")
		append('}')
	}
}