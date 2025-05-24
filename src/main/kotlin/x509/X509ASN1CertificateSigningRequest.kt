package org.bread_experts_group.acme_microserver.x509

import org.bread_experts_group.acme_microserver.asn1.element.ASN1BitString
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Boolean
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Integer
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Null
import org.bread_experts_group.acme_microserver.asn1.element.ASN1OctetString
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Sequence
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Set
import org.bread_experts_group.acme_microserver.asn1.element.ASN1Tagged
import org.bread_experts_group.acme_microserver.asn1.element.ASN1UTFString
import org.bread_experts_group.acme_microserver.jws.JSONWebKey.Companion.to48Bytes
import org.bread_experts_group.acme_microserver.x509.X509ASN1Certificate.Companion.ATTRIBUTE_COMMON_NAME
import org.bread_experts_group.acme_microserver.x509.X509ASN1Certificate.Companion.ECDSA_WITH_SHA_512
import org.bread_experts_group.acme_microserver.x509.X509ASN1Certificate.Companion.EC_PUBLIC_KEY
import org.bread_experts_group.acme_microserver.x509.X509ASN1Certificate.Companion.EXTENSION_REQUEST
import org.bread_experts_group.acme_microserver.x509.X509ASN1Certificate.Companion.EXTENSION_SUBJECT_ALT_NAME
import org.bread_experts_group.acme_microserver.x509.X509ASN1Certificate.Companion.SECP384R1
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey

class X509ASN1CertificateSigningRequest(
	keyPair: KeyPair,
	names: List<String>
) {
	val certificationRequest = ASN1Sequence(
		ASN1Integer(0),
		ASN1Sequence(
			ASN1Set(
				ASN1Sequence(
					ATTRIBUTE_COMMON_NAME,
					ASN1UTFString(names.first())
				)
			)
		),
		ASN1Sequence(
			ASN1Sequence(
				EC_PUBLIC_KEY,
				SECP384R1
			),
			ASN1BitString(
				byteArrayOf(
					0x04,
					*(keyPair.public as ECPublicKey).w.affineX.to48Bytes(),
					*(keyPair.public as ECPublicKey).w.affineY.to48Bytes()
				)
			)
		),
		ASN1Tagged(
			0, true,
			ASN1Sequence(
				EXTENSION_REQUEST,
				ASN1Set(
					ASN1Sequence(
						ASN1Sequence(
							EXTENSION_SUBJECT_ALT_NAME,
							ASN1Boolean(false),
							ASN1OctetString(
								ASN1Sequence(
									*names.map {
										ASN1Tagged(
											2, false,
											ASN1UTFString(it)
										)
									}.toTypedArray()
								).asBytes()
							)
						)
					)
				)
			)
		)
	)

	val csr = ASN1Sequence(
		certificationRequest,
		ASN1Sequence(
			ECDSA_WITH_SHA_512,
			ASN1Null()
		),
		Signature.getInstance("SHA512withECDSA").let {
			it.initSign(keyPair.private)
			it.update(certificationRequest.asBytes())
			ASN1BitString(it.sign())
		}
	)
}