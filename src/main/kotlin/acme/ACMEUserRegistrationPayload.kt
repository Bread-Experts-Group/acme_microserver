package org.bread_experts_group.acme_microserver

import org.bread_experts_group.coder.fixed.json.JSONConvertible

data class ACMEUserRegistrationPayload(
	val contact: Array<String>,
	val termsOfServiceAgreed: Boolean = true,
	val onlyReturnExisting: Boolean = false
) : JSONConvertible {
	override fun toJSON(): String = buildString {
		append('{')
		append("\"contact\":[")
		append(contact.joinToString(",") { "\"$it\"" })
		append("],\"termsOfServiceAgreed\":$termsOfServiceAgreed,")
		append("\"onlyReturnExisting\":$onlyReturnExisting")
		append('}')
	}

	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (javaClass != other?.javaClass) return false

		other as ACMEUserRegistrationPayload

		if (termsOfServiceAgreed != other.termsOfServiceAgreed) return false
		if (onlyReturnExisting != other.onlyReturnExisting) return false
		if (!contact.contentEquals(other.contact)) return false

		return true
	}

	override fun hashCode(): Int {
		var result = termsOfServiceAgreed.hashCode()
		result = 31 * result + onlyReturnExisting.hashCode()
		result = 31 * result + contact.contentHashCode()
		return result
	}
}