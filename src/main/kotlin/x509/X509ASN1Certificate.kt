package org.bread_experts_group.acme_microserver.x509

import org.bread_experts_group.acme_microserver.asn1.element.ASN1BitString
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Boolean
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Integer
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Null
import org.bread_experts_group.acme_microserver.asn1.element.ASN1ObjectIdentifier
import org.bread_experts_group.acme_microserver.asn1.element.ASN1OctetString
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Sequence
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Tagged
import org.bread_experts_group.acme_microserver.asn1.element.ASN1UTCTime
import org.bread_experts_group.acme_microserver.asn1.element.ASN1UTFString
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Set
import org.bread_experts_group.acme_microserver.jws.JSONWebKey.Companion.to32Bytes
import java.math.BigInteger
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.time.ZonedDateTime

/**
 * #### !!! Not designated for normal use (yet) !!!
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5280">IETF RFC 5280</a>:
 * Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
 */
class X509ASN1Certificate(
	keyPair: KeyPair,
	commonName: String,
	keyAuthorization: ByteArray
) {
	companion object {
		const val OID_CURVE_PRIME_FIELD = 0
		const val OID_ISO = 1
		const val OID_INTERNET = 1
		const val OID_PRIVATE_EXTENSION = 1
		const val OID_NAMED_CURVES_PRIME_FIELDS = 1
		const val OID_PUBLIC_KEY_CRYPTOGRAPHY_STANDARDS = 1
		const val OID_JOINT_ISO_CCITT = 2
		const val OID_MEMBER_BODY = 2
		const val OID_PUBLIC_KEY_TYPES = 2
		const val OID_ELLIPTIC_CURVE_DOMAIN_PARAMETERS = 3
		const val OID_IDENTIFIED_ORGANIZATION = 3
		const val OID_ECDSA_WITH_SHA2 = 3
		const val OID_SIGNATURES = 4
		const val OID_SECURITY = 5
		const val OID_DIRECTORY_SERVICES = 5
		const val OID_MECHANISMS = 5
		const val OID_DEPARTMENT_OF_DEFENSE = 6
		const val OID_PKIX = 7
		const val OID_PKCS_9 = 9
		const val OID_CERTIFICATE_EXTENSIONS = 29
		const val OID_STANDARDS_FOR_EFFICIENT_CRYPTOGRAPHY_GROUP = 132
		const val OID_UNITED_STATES_ANSI = 840
		const val OID_ANSI_X9_62 = 10045
		const val OID_RSA_DATA_SECURITY_INC = 113549

		// Object Identifiers
		val ATTRIBUTE_COMMON_NAME = ASN1ObjectIdentifier( // id-at
			OID_JOINT_ISO_CCITT, OID_DIRECTORY_SERVICES, 4,
			3
		)
		val EXTENSION_SUBJECT_ALT_NAME = ASN1ObjectIdentifier( // id-ce
			OID_JOINT_ISO_CCITT, OID_DIRECTORY_SERVICES, OID_CERTIFICATE_EXTENSIONS,
			17
		)
		val EXTENSION_BASIC_CONSTRAINTS = ASN1ObjectIdentifier( // id-ce
			OID_JOINT_ISO_CCITT, OID_DIRECTORY_SERVICES, OID_CERTIFICATE_EXTENSIONS,
			19
		)
		val EXTENSION_ACME = ASN1ObjectIdentifier( // id-pe
			OID_ISO, OID_IDENTIFIED_ORGANIZATION, OID_DEPARTMENT_OF_DEFENSE,
			OID_INTERNET, OID_SECURITY, OID_MECHANISMS, OID_PKIX, OID_PRIVATE_EXTENSION,
			31
		)
		val EXTENSION_REQUEST = ASN1ObjectIdentifier(
			OID_ISO, OID_MEMBER_BODY, OID_UNITED_STATES_ANSI,
			OID_RSA_DATA_SECURITY_INC, OID_PUBLIC_KEY_CRYPTOGRAPHY_STANDARDS, OID_PKCS_9,
			14
		)
		val EC_PUBLIC_KEY = ASN1ObjectIdentifier(
			OID_ISO, OID_MEMBER_BODY, OID_UNITED_STATES_ANSI,
			OID_ANSI_X9_62, OID_PUBLIC_KEY_TYPES,
			1
		)
		val SECP256R1 = ASN1ObjectIdentifier(
			OID_ISO, OID_MEMBER_BODY, OID_UNITED_STATES_ANSI,
			OID_ANSI_X9_62, OID_ELLIPTIC_CURVE_DOMAIN_PARAMETERS, OID_NAMED_CURVES_PRIME_FIELDS,
			7
		)
		val SECP384R1 = ASN1ObjectIdentifier(
			OID_ISO, OID_IDENTIFIED_ORGANIZATION, OID_STANDARDS_FOR_EFFICIENT_CRYPTOGRAPHY_GROUP,
			OID_CURVE_PRIME_FIELD,
			34
		)
		val SECP521R1 = ASN1ObjectIdentifier(
			OID_ISO, OID_IDENTIFIED_ORGANIZATION, OID_STANDARDS_FOR_EFFICIENT_CRYPTOGRAPHY_GROUP,
			OID_CURVE_PRIME_FIELD,
			35
		)
		val ECDSA_WITH_SHA_224 = ASN1ObjectIdentifier(
			OID_ISO, OID_MEMBER_BODY, OID_UNITED_STATES_ANSI,
			OID_ANSI_X9_62, OID_SIGNATURES, OID_ECDSA_WITH_SHA2,
			1
		)
		val ECDSA_WITH_SHA_256 = ASN1ObjectIdentifier(
			OID_ISO, OID_MEMBER_BODY, OID_UNITED_STATES_ANSI,
			OID_ANSI_X9_62, OID_SIGNATURES, OID_ECDSA_WITH_SHA2,
			2
		)
		val ECDSA_WITH_SHA_384 = ASN1ObjectIdentifier(
			OID_ISO, OID_MEMBER_BODY, OID_UNITED_STATES_ANSI,
			OID_ANSI_X9_62, OID_SIGNATURES, OID_ECDSA_WITH_SHA2,
			3
		)
		val ECDSA_WITH_SHA_512 = ASN1ObjectIdentifier(
			OID_ISO, OID_MEMBER_BODY, OID_UNITED_STATES_ANSI,
			OID_ANSI_X9_62, OID_SIGNATURES, OID_ECDSA_WITH_SHA2,
			4
		)
	}

	val tbsCertificate = ASN1Sequence(
		ASN1Tagged(0, true, ASN1Integer(2)),
		ASN1Integer(BigInteger("B4EAD", 16)),
		ASN1Sequence(
			ECDSA_WITH_SHA_512,
			ASN1Null()
		),
		ASN1Sequence(
			ASN1Set(
				ASN1Sequence(
					ATTRIBUTE_COMMON_NAME,
					ASN1UTFString(commonName)
				)
			)
		),
		ASN1Sequence(
			ASN1UTCTime(ZonedDateTime.now()),
			ASN1UTCTime(ZonedDateTime.now().plusDays(5))
		),
		ASN1Sequence(
			ASN1Set(
				ASN1Sequence(
					ATTRIBUTE_COMMON_NAME,
					ASN1UTFString(commonName)
				)
			)
		),
		ASN1Sequence(
			ASN1Sequence(
				EC_PUBLIC_KEY,
				SECP256R1
			),
			ASN1BitString(
				byteArrayOf(
					0x04,
					*(keyPair.public as ECPublicKey).w.affineX.to32Bytes(),
					*(keyPair.public as ECPublicKey).w.affineY.to32Bytes()
				)
			)
		),
		ASN1Tagged( // Extensions
			3, true, ASN1Sequence(
				ASN1Sequence(
					EXTENSION_BASIC_CONSTRAINTS,
					ASN1Boolean(true),
					ASN1OctetString(
						ASN1Sequence(
							ASN1Boolean(false)
						).asBytes()
					)
				),
				ASN1Sequence(
					EXTENSION_SUBJECT_ALT_NAME,
					ASN1Boolean(false),
					ASN1OctetString(
						ASN1Sequence(
							ASN1Tagged(
								2, false,
								ASN1OctetString(commonName.toByteArray(Charsets.US_ASCII))
							)
						).asBytes()
					)
				),
				ASN1Sequence(
					EXTENSION_ACME,
					ASN1Boolean(true),
					ASN1OctetString(
						ASN1OctetString(keyAuthorization).asBytes()
					)
				)
			)
		)
	)

	val x509 = ASN1Sequence(
		tbsCertificate,
		ASN1Sequence(
			ECDSA_WITH_SHA_512,
			ASN1Null()
		),
		Signature.getInstance("SHA512withECDSA").let {
			it.initSign(keyPair.private)
			it.update(tbsCertificate.asBytes())
			ASN1BitString(it.sign())
		}
	)
}