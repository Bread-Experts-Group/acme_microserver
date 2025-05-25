package org.bread_experts_group.acme_microserver.handler

import org.bread_experts_group.MultipleArgs
import org.bread_experts_group.SingleArgs
import org.bread_experts_group.acme_microserver.ACMEAuthorization
import org.bread_experts_group.acme_microserver.ACMEChallenge
import org.bread_experts_group.acme_microserver.jws.JSONWebKey
import org.bread_experts_group.acme_microserver.x509.X509ASN1Certificate
import org.bread_experts_group.stream.writeString
import java.io.ByteArrayInputStream
import java.io.File
import java.net.InetSocketAddress
import java.security.KeyPair
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.logging.Logger
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

class TLSALPN01Handler : ACMEChallengeHandler {
	override fun identifier(): String = "tls-alpn-01"
	override fun defaultPreference(): Int = 2

	override fun handle(
		singleArgs: SingleArgs,
		multipleArgs: MultipleArgs,
		jwsKeyPair: KeyPair,
		jsonWebKey: JSONWebKey,
		authorization: ACMEAuthorization,
		challenge: ACMEChallenge,
		localFileBase: File,
		authLogger: Logger
	): Triple<Thread, CountDownLatch, CountDownLatch> {
		val serverSocket = X509ASN1Certificate(
			jwsKeyPair,
			authorization.identifier.value,
			MessageDigest
				.getInstance("SHA-256")
				.digest("${challenge.token}.${jsonWebKey.thumbprint()}".toByteArray())
		).x509.asBytes().let { x509Bytes ->
			if (singleArgs.getValue("tls_alpn_01_save_temporary_certificate") as Boolean) {
				localFileBase.mkdirs()
				localFileBase
					.resolve("alpn-01.crt")
					.writeBytes(x509Bytes)
			}
			val certFactory = CertificateFactory.getInstance("X.509")
			val cert = certFactory.generateCertificate(ByteArrayInputStream(x509Bytes)) as X509Certificate
			val keyStore = KeyStore.getInstance("JKS")
			keyStore.load(null, null)
			keyStore.setKeyEntry("alias", jwsKeyPair.private, charArrayOf('!'), arrayOf(cert))
			val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
			kmf.init(keyStore, charArrayOf('!'))

			val sslContext = SSLContext.getInstance("TLS")
			sslContext.init(kmf.keyManagers, null, null)
			sslContext.serverSocketFactory
		}

		val localServer = serverSocket.createServerSocket() as SSLServerSocket
		localServer.bind(
			InetSocketAddress(
				singleArgs.getValue("tls_alpn_01_ip") as String,
				singleArgs.getValue("tls_alpn_01_port") as Int
			)
		)
		val parameters = localServer.sslParameters
		parameters.applicationProtocols = arrayOf("acme-tls/1")
		localServer.sslParameters = parameters
		val rendezvous = CountDownLatch(1)
		val block = CountDownLatch(1)
		val serverThread = Thread.ofVirtual().start {
			authLogger.info("Server active; ${localServer.localSocketAddress}")
			while (!Thread.interrupted()) {
				try {
					rendezvous.countDown()
					val sock = localServer.accept() as SSLSocket
					sock.startHandshake()
					authLogger.info {
						"Got connection [${sock.remoteSocketAddress}] for [${sock.applicationProtocol}]"
					}
					if (sock.applicationProtocol != "acme-tls/1") {
						sock.close()
						continue
					}
					sock.outputStream.writeString("HTTP/1.1 200\r\nContent-Length:9\r\n\r\nHello SSL")
					block.countDown()
				} catch (_: Exception) {
				}
			}
			authLogger.info("Going offline.")
			localServer.close()
		}
		return Triple(serverThread, rendezvous, block)
	}
}