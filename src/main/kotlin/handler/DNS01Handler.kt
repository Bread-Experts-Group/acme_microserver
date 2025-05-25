package org.bread_experts_group.acme_microserver.handler

import org.bread_experts_group.MultipleArgs
import org.bread_experts_group.SingleArgs
import org.bread_experts_group.acme_microserver.ACMEAuthorization
import org.bread_experts_group.acme_microserver.ACMEChallenge
import org.bread_experts_group.acme_microserver.jws.JSONWebKey
import java.io.File
import java.security.KeyPair
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.logging.Logger

class DNS01Handler : ACMEChallengeHandler {
	override fun identifier(): String = "dns-01"
	override fun defaultPreference(): Int = 0

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
		val countedDown = CountDownLatch(1)
		val challengeResponse = Base64.getUrlEncoder().withoutPadding().encode(
			MessageDigest
				.getInstance("SHA-256")
				.digest("${challenge.token}.${jsonWebKey.thumbprint()}".toByteArray())
		).decodeToString()
		authLogger.info {
			buildString {
				appendLine("--- DNS Reconfiguration Required ---")
				appendLine("_acme-challenge.${authorization.identifier.value}\tTXT\t\"$challengeResponse\"")
				append("Input when ready...")
			}
		}
		readln()
		countedDown.countDown()
		// TODO: Setup local DNS server if detection succeeds
//		val localServer = ServerSocket()
//		localServer.bind(
//			InetSocketAddress(
//				singleArgs.getValue("dns_01_ip") as String,
//				singleArgs.getValue("dns_01_port") as Int
//			)
//		)
//		val rendezvous = CountDownLatch(1)
//		val block = CountDownLatch(1)
//		val serverThread = Thread.ofVirtual().start {
//			authLogger.info("Server active; ${localServer.localSocketAddress}")
//			while (!Thread.interrupted()) {
//				try {
//					rendezvous.countDown()
//					val sock = localServer.accept()
//					val request = HTTPRequest.read(sock.inputStream)
//					authLogger.info { "Got connection [${sock.remoteSocketAddress}] for [${request.path.path}]" }
//					if (request.path.path == "/.well-known/acme-challenge/${challenge.token}") {
//						val contents = "${challenge.token}.${jsonWebKey.thumbprint()}"
//						sock.outputStream.writeString(
//							"HTTP/1.1 200\r\nContent-Length:${contents.length}\r\n\r\n$contents"
//						)
//						block.countDown()
//					}
//				} catch (_: Exception) {
//				}
//			}
//			authLogger.info("Going offline.")
//			localServer.close()
//		}
		return Triple(Thread.startVirtualThread {}, countedDown, countedDown)
	}
}