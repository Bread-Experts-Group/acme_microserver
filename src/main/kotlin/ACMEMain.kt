package org.bread_experts_group.acme_microserver

import org.bread_experts_group.ACMEAuthorization
import org.bread_experts_group.ACMEChallenge
import org.bread_experts_group.ACMEDirectory
import org.bread_experts_group.ACMEOrder
import org.bread_experts_group.ACMEOrderPlacement
import org.bread_experts_group.ACMEOrderResponse
import org.bread_experts_group.ACMEUserRegistrationPayload
import org.bread_experts_group.Flag
import org.bread_experts_group.crypto.KeyPairFile
import org.bread_experts_group.crypto.read
import org.bread_experts_group.crypto.restrictToLocal
import org.bread_experts_group.acme_microserver.handler.ACMEChallengeHandler
import org.bread_experts_group.jws.JSONWebKey
import org.bread_experts_group.jws.JSONWebKeyProtectedHeader
import org.bread_experts_group.jws.JSONWebSignatureSignedData
import org.bread_experts_group.x509.X509ASN1CertificateSigningRequest
import org.bread_experts_group.coder.fixed.json.JSONConvertible
import org.bread_experts_group.logging.ColoredLogger
import org.bread_experts_group.readArgs
import org.bread_experts_group.stringToBoolean
import org.bread_experts_group.stringToInt
import org.bread_experts_group.stringToURI
import java.io.File
import java.io.FileOutputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.ServiceLoader
import kotlin.io.path.deleteIfExists
import kotlin.io.path.readText

fun createP12Keystore(
	privateKey: PrivateKey,
	certificate: String,
	password: CharArray
): KeyStore {
	val decoder = Base64.getDecoder()
	val certFactory = CertificateFactory.getInstance("X.509")
	@Suppress("UNCHECKED_CAST") val certificates = certificate
		.split("-----END CERTIFICATE-----")
		.parallelStream()
		.map { it.substringAfter("-----BEGIN CERTIFICATE-----") }
		.map { it.replace("\\s".toRegex(), "") }
		.filter { it.isNotEmpty() }
		.map { certFactory.generateCertificate(decoder.decode(it).inputStream()) as X509Certificate }
		.toList()
		.toTypedArray()
	val keyStore = KeyStore.getInstance("PKCS12")
	keyStore.load(null, null)
	keyStore.setKeyEntry("cert", privateKey, password, certificates)
	return keyStore
}

fun main(args: Array<String>) {
	val logger = ColoredLogger.newLogger("ACME Microserver Main")
	logger.info("Loading ACME challenge handlers ...")
	val handlers = ServiceLoader.load(ACMEChallengeHandler::class.java)
		.associateBy { it.identifier() }
		.toMutableMap()
	val handlersPreferenceOrder = handlers
		.map { it.value }
		.toMutableList()
	handlersPreferenceOrder.sortByDescending { it.defaultPreference() }
	logger.info("Loaded ACME challenge handlers: [${handlersPreferenceOrder.joinToString(",") { it.identifier() }}]")
	val (singleArgs, multipleArgs) = readArgs(
		args,
		"acme_microserver",
		"Distribution of software for Bread Experts Group operated ACME clients/facilitators.",
		Flag(
			"acme_directory",
			"The ACME directory URL this program will search for to acquire \"newNonce\", \"newAccount\", ...",
			default = URI("https://acme-v02.api.letsencrypt.org/directory"),
			conv = ::stringToURI
		),
		Flag<String>(
			"acme_profile",
			"The ACME profile used for orders; see the acme_directory for supported profiles."
		),
		Flag<String>(
			"contact",
			"A contact on which to register a new ACME account on.",
			required = 1,
			repeatable = true
		),
		Flag(
			"jws_public_key",
			"The public key used for signing requests. A new one will be generated if it does not exist.",
			default = "jws_public.der"
		),
		Flag(
			"jws_private_key",
			"The private key used for signing requests. A new one will be generated if it does not exist.",
			default = "jws_private.der"
		),
		Flag(
			"crt_public_key",
			"The public key used for certificate requests. A new one will be generated if it does not exist.",
			default = "crt_public.der"
		),
		Flag(
			"crt_private_key",
			"The private key used for certificate requests. A new one will be generated if it does not exist.",
			default = "crt_private.der"
		),
		Flag<String>(
			"domain",
			"Obtain new orders under the listed (sub)domains.",
			required = 1,
			repeatable = true
		),
		Flag(
			"immediate",
			"Order a keystore for the listed domains immediately. The local renewal service will not be started.",
			default = true,
			conv = ::stringToBoolean
		),
		Flag(
			"keystore",
			"Deposit the ordered certificates under the specified PKCS #12 keystore" +
					"(a timestamp and extension of .p12 will be added).",
			default = "keystore"
		),
		Flag<String>(
			"keystore_passphrase",
			"The passphrase used to lock the keystore.",
			required = 1
		),
		Flag(
			"tls_alpn_01_save_temporary_certificate",
			"Save the temporary self-signed certificate used for verifying TLS-ALPN-01.",
			default = false,
			conv = ::stringToBoolean
		),
		Flag(
			"tls_alpn_01_ip",
			"The IP used for the verification server for TLS-ALPN-01.",
			default = "0.0.0.0"
		),
		Flag(
			"tls_alpn_01_port",
			"The TCP port used for the verification server for TLS-ALPN-01.",
			default = 443,
			conv = ::stringToInt
		),
		Flag(
			"http_01_ip",
			"The IP used for the verification server for HTTP-01.",
			default = "0.0.0.0"
		),
		Flag(
			"http_01_port",
			"The TCP port used for the verification server for HTTP-01.",
			default = 80,
			conv = ::stringToInt
		),
		Flag(
			"dns_01_ip",
			"The IP used for the verification server for HTTP-01.",
			default = "0.0.0.0"
		),
		Flag(
			"dns_01_port",
			"The TCP / UDP port used for the verification server for DNS-01.",
			default = 53,
			conv = ::stringToInt
		),
		Flag(
			"save_certificate_sign_requests",
			"Save the Certificate Signing Requests used in finalization.",
			default = false,
			conv = ::stringToBoolean
		),
		Flag(
			"save_location",
			"Save certificates for sites at the specified location.",
			default = "./acme"
		),
		Flag(
			"link",
			"Specifies the file linking options for acme/<acme service>/latest.p12.\n" +
					"[${P12FileLinkOption.entries.joinToString(",\n ") { "${it.name}: ${it.description}" }}]",
			default = P12FileLinkOption.FS_HARD_LINK,
			conv = { P12FileLinkOption.valueOf(it) }
		),
		Flag(
			"challenge_preference",
			"Specifies the order of preference challenges will be done in. All challenges must be specified.",
			default = handlersPreferenceOrder.joinToString(",") { it.identifier() },
			conv = {
				val setHandlers = it.split(',')
				setHandlers.forEach { set ->
					if (!handlers.containsKey(set)) throw IllegalArgumentException("Challenge [$set] is not loaded.")
				}
				if (setHandlers.size != handlers.size)
					throw IllegalArgumentException("You must specify all challenges for preference order.")
				var i = 0
				val redefined = setHandlers.associateWith { i++ }
				handlersPreferenceOrder.sortBy { h -> redefined[h.identifier()] }
				logger.info {
					"Sorted ACME challenge handlers: [${
						handlersPreferenceOrder.joinToString(",") { h -> h.identifier() }
					}]"
				}
			}
		),
		Flag(
			"disable_challenges",
			"Disables the specified challenges.",
			default = "",
			conv = {
				val setHandlers = it.split(',')
				setHandlers.forEach { set ->
					if (!handlers.containsKey(set)) throw IllegalArgumentException("Challenge [$set] is not loaded.")
					handlers.remove(set)
					handlersPreferenceOrder.removeIf { h -> h.identifier() == set }
				}
			}
		)
	)
	logger.info("Creating JSON web key (JWK) along w/ keypair")
	val directorySource = singleArgs.getValue("acme_directory") as URI
	val fileBase = File(singleArgs.getValue("save_location") as String)
		.resolve(directorySource.host)
	fileBase.mkdirs()
	logger.info("Restricting [${fileBase.canonicalPath}] to the local user only")
	fileBase.restrictToLocal()
	val jwsKeyPairFile = KeyPairFile(
		fileBase.resolve(singleArgs.getValue("jws_public_key") as String),
		fileBase.resolve(singleArgs.getValue("jws_private_key") as String)
	)
	val (jsonWebKey, jwsKeyPair) = JSONWebKey.newEclipticCurveJWT(jwsKeyPairFile)
	logger.info("JWK: ${jsonWebKey.toString().replace(",", ",\n")}\nPublic Key: ${jwsKeyPair.public}")
	val httpClient = HttpClient.newHttpClient()
	val directory = run {
		logger.info {
			"Getting directory information [$directorySource]"
		}
		val directoryReturned = httpClient.send(
			HttpRequest
				.newBuilder(directorySource)
				.method("GET", HttpRequest.BodyPublishers.noBody())
				.build(),
			HttpResponse.BodyHandlers.ofInputStream()
		)
		logger.info {
			"Directory returned ${directoryReturned.statusCode()}, parsing"
		}
		val parsed = ACMEDirectory.read(directoryReturned.body())
		logger.info {
			"Directory: ${parsed.toString().replace(",", ",\n")}"
		}
		parsed
	}

	fun getNonce(): String {
		logger.fine { "Getting nonce [${directory.newNonce}]" }
		val nonceReturned = httpClient.send(
			HttpRequest
				.newBuilder(directory.newNonce)
				.method("HEAD", HttpRequest.BodyPublishers.noBody())
				.build(),
			HttpResponse.BodyHandlers.discarding()
		)
		val nonce = nonceReturned.headers().firstValue("Replay-Nonce").get()
		logger.fine { "newNonce returned ${nonceReturned.statusCode()}: [$nonce]" }
		return nonce
	}

	val userAccount = run {
		val contactDetails = multipleArgs.getValue("contact")
		logger.info("Creating ACME account [${directory.newAccount}]")
		val protected = JSONWebKeyProtectedHeader("ES256", getNonce(), directory.newAccount, jsonWebKey)

		@Suppress("UNCHECKED_CAST")
		val payload = ACMEUserRegistrationPayload((contactDetails as List<String>).toTypedArray())
		val signedData = JSONWebSignatureSignedData.createSignedData(protected, payload, jwsKeyPair)
		val userReturned = httpClient.send(
			HttpRequest
				.newBuilder(directory.newAccount)
				.header("Content-Type", "application/jose+json")
				.method("POST", HttpRequest.BodyPublishers.ofString(signedData.toJSON()))
				.build(),
			HttpResponse.BodyHandlers.ofString()
		)
		val location = URI(userReturned.headers().firstValue("Location").get())
		val status = when (val status = userReturned.statusCode()) {
			200 -> "retrieved"
			201 -> "created"
			else -> throw IllegalStateException("Unknown status code: $status")
		}
		logger.info("Account $status: ${userReturned.statusCode()} [$location]")
		location
	}
	var lastOrder: URI? = null
	fun sendOrder(): ACMEOrderResponse {
		val payload = if (lastOrder == null) {
			logger.info("Placing ACME order [${directory.newOrder}]")
			ACMEOrderPlacement(buildList {
				multipleArgs.getValue("domain").forEach {
					it as String
					add(ACMEOrder("dns", it))
				}
			}, singleArgs["acme_profile"] as? String)
		} else {
			logger.info("Checking ACME order [$lastOrder]")
			object : JSONConvertible {
				override fun toJSON(): String = ""
			}
		}
		val protected = JSONWebKeyProtectedHeader(
			"ES256", getNonce(),
			lastOrder ?: directory.newOrder, userAccount.toString()
		)
		val signedData = JSONWebSignatureSignedData.createSignedData(protected, payload, jwsKeyPair)
		val newOrder = httpClient.send(
			HttpRequest
				.newBuilder(lastOrder ?: directory.newOrder)
				.header("Content-Type", "application/jose+json")
				.method("POST", HttpRequest.BodyPublishers.ofString(signedData.toJSON()))
				.build(),
			HttpResponse.BodyHandlers.ofInputStream()
		)
		newOrder.headers().firstValue("Location").ifPresent { lastOrder = URI(it) }
		return ACMEOrderResponse.read(newOrder.body())
	}

	val thisRunBase = fileBase.resolve(System.currentTimeMillis().toString())
	thisRunBase.mkdir()
	val orderResponse = sendOrder()
	logger.info("Order [$lastOrder] placed with [${orderResponse.authorizations.size}] authorizations")
	orderResponse.authorizations.forEachIndexed { i, authorizationURI ->
		val authLogger = ColoredLogger.newLogger(
			"ACME Authorization [${i + 1}/${orderResponse.authorizations.size}]"
		)
		authLogger.info("Starting on $authorizationURI ...")
		val authorizationResponse = run {
			val payload = object : JSONConvertible {
				override fun toJSON(): String = ""
			}
			val protected = JSONWebKeyProtectedHeader("ES256", getNonce(), authorizationURI, userAccount.toString())
			val signedData = JSONWebSignatureSignedData.createSignedData(protected, payload, jwsKeyPair)
			httpClient.send(
				HttpRequest
					.newBuilder(authorizationURI)
					.header("Content-Type", "application/jose+json")
					.method("POST", HttpRequest.BodyPublishers.ofString(signedData.toJSON()))
					.build(),
				HttpResponse.BodyHandlers.ofInputStream()
			)
		}
		val authorization = ACMEAuthorization.read(authorizationResponse.body())
		val localFileBase = thisRunBase.resolve(authorization.identifier.value + '/')
		val typedChallenges = authorization.challenges.associateBy { it.type }
		val challengeParameters = handlersPreferenceOrder.firstNotNullOfOrNull {
			val challenge = typedChallenges[it.identifier()]
			if (challenge != null) challenge to it
			else null
		}
		if (challengeParameters == null) throw IllegalStateException(
			"No challenge was supported for ${authorization.identifier.value}\nChallenges: ${authorization.challenges}"
		)
		val (challenge, handler) = challengeParameters
		val (thread, rendezvous, block) = handler.handle(
			singleArgs, multipleArgs,
			jwsKeyPair, jsonWebKey,
			authorization, challenge,
			localFileBase, authLogger
		)

		fun sendCheck(status: Boolean): ACMEChallenge {
			authLogger.info {
				val first = if (status) "Checking challenge status ..."
				else "Initiating challenge ..."
				first + " [${challenge.url} / ${challenge.token}]"
			}
			val payload = object : JSONConvertible {
				override fun toJSON(): String = if (status) "" else "{}"
			}
			val protected = JSONWebKeyProtectedHeader(
				"ES256", getNonce(),
				challenge.url, userAccount.toString()
			)
			val signedData = JSONWebSignatureSignedData.createSignedData(protected, payload, jwsKeyPair)
			return ACMEChallenge.read(
				httpClient.send(
					HttpRequest
						.newBuilder(challenge.url)
						.header("Content-Type", "application/jose+json")
						.method("POST", HttpRequest.BodyPublishers.ofString(signedData.toJSON()))
						.build(),
					HttpResponse.BodyHandlers.ofInputStream()
				).body()
			)
		}

		rendezvous.await()
		var challengeStatus = sendCheck(false)
		while (true) {
			authLogger.info("Challenge status: ${challengeStatus.status}")
			if (challengeStatus.status != "pending") break
			block.await()
			Thread.sleep(5000)
			challengeStatus = sendCheck(true)
		}
		thread.interrupt()
	}
	val crtKeyPair = KeyPairFile(
		thisRunBase.resolve(singleArgs.getValue("crt_public_key") as String),
		thisRunBase.resolve(singleArgs.getValue("crt_private_key") as String)
	).read("secp384r1")
	run {
		val names = orderResponse.identifiers.map { it.value }
		val csr = X509ASN1CertificateSigningRequest(crtKeyPair, names).csr
		if (singleArgs.getValue("save_certificate_sign_requests") as Boolean)
			thisRunBase
				.resolve("csr.p10")
				.writeBytes(csr.asBytes())
		val payload = object : JSONConvertible {
			override fun toJSON(): String = buildString {
				append('{')
				append("\"csr\":\"")
				append(Base64.getUrlEncoder().withoutPadding().encode(csr.asBytes()).decodeToString())
				append("\"}")
			}
		}
		val protected = JSONWebKeyProtectedHeader(
			"ES256", getNonce(),
			orderResponse.finalize, userAccount.toString()
		)
		val signedData = JSONWebSignatureSignedData.createSignedData(protected, payload, jwsKeyPair)
		val finalizeResponse = ACMEOrderResponse.read(
			httpClient.send(
				HttpRequest
					.newBuilder(orderResponse.finalize)
					.header("Content-Type", "application/jose+json")
					.method(
						"POST",
						HttpRequest.BodyPublishers.ofString(signedData.toJSON())
					)
					.build(),
				HttpResponse.BodyHandlers.ofInputStream()
			).body()
		)
		logger.info { "Requested finalization $names [${finalizeResponse.status}]" }
	}
	run {
		var orderCheck = sendOrder()
		while (true) {
			logger.info("Checking order ... [${orderCheck.status}]")
			if (orderCheck.status != "processing") break
			Thread.sleep(5000)
			orderCheck = sendOrder()
		}
		val certificate = orderCheck.certificate!!
		logger.info("Downloading certificate [$certificate] ...")
		val certificateFile = thisRunBase
			.resolve("verified.crt")
			.toPath()
		val certificateDownload = httpClient.send(
			HttpRequest
				.newBuilder(certificate)
				.method("GET", HttpRequest.BodyPublishers.noBody())
				.build(),
			HttpResponse.BodyHandlers.ofFile(certificateFile)
		)
		logger.info {
			"Certificate downloaded [${certificateDownload.statusCode()}] to ${certificateFile.toFile().canonicalPath}"
		}
		logger.info("Creating keystore ...")
		val pwd = (singleArgs.getValue("keystore_passphrase") as String).toCharArray()
		val keystore = createP12Keystore(
			crtKeyPair.private,
			certificateFile.readText(),
			pwd
		)
		logger.info("Saving keystore ...")
		val keystoreFile = thisRunBase.resolve(
			"${singleArgs.getValue("keystore") as String}.p12"
		).canonicalFile
		FileOutputStream(keystoreFile).use { keystore.store(it, pwd) }
		logger.info("Keystore saved at [${keystoreFile.canonicalPath}]")
		val linkPath = fileBase.resolve("latest.p12").canonicalFile.toPath()
		when (singleArgs.getValue("link") as P12FileLinkOption) {
			P12FileLinkOption.NO_LINK -> {}

			P12FileLinkOption.FS_SOFT_LINK -> {
				linkPath.deleteIfExists()
				Files.createSymbolicLink(linkPath, keystoreFile.toPath())
				logger.info("Keystore soft link created [$linkPath]")
			}

			P12FileLinkOption.FS_HARD_LINK -> {
				linkPath.deleteIfExists()
				Files.createLink(linkPath, keystoreFile.toPath())
				logger.info("Keystore hard link created [$linkPath]")
			}

			P12FileLinkOption.COPY -> {
				Files.copy(keystoreFile.toPath(), linkPath)
				logger.info("Keystore copied in accordance with link [$linkPath]")
			}
		}
	}
}