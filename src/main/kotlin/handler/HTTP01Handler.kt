package org.bread_experts_group.acme_microserver.handler

import org.bread_experts_group.MultipleArgs
import org.bread_experts_group.SingleArgs
import org.bread_experts_group.acme_microserver.ACMEAuthorization
import org.bread_experts_group.acme_microserver.ACMEChallenge
import org.bread_experts_group.acme_microserver.jws.JSONWebKey
import org.bread_experts_group.http.HTTPRequest
import org.bread_experts_group.stream.writeString
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.KeyPair
import java.util.concurrent.CountDownLatch
import java.util.logging.Logger

class HTTP01Handler : ACMEChallengeHandler {
	override fun identifier(): String = "http-01"
	override fun defaultPreference(): Int = 1

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
		val localServer = ServerSocket()
		localServer.bind(
			InetSocketAddress(
				singleArgs.getValue("http_01_ip") as String,
				singleArgs.getValue("http_01_port") as Int
			)
		)
		val rendezvous = CountDownLatch(1)
		val block = CountDownLatch(1)
		val serverThread = Thread.ofVirtual().start {
			authLogger.info("Server active; ${localServer.localSocketAddress}")
			while (!Thread.interrupted()) {
				try {
					rendezvous.countDown()
					val sock = localServer.accept()
					val request = HTTPRequest.read(sock.inputStream)
					authLogger.info { "Got connection [${sock.remoteSocketAddress}] for [${request.path.path}]" }
					if (request.path.path == "/.well-known/acme-challenge/${challenge.token}") {
						val contents = "${challenge.token}.${jsonWebKey.thumbprint()}"
						sock.outputStream.writeString(
							"HTTP/1.1 200\r\nContent-Length:${contents.length}\r\n\r\n$contents"
						)
						block.countDown()
					}
				} catch (_: Exception) {
				}
			}
			authLogger.info("Going offline.")
			localServer.close()
		}
		return Triple(serverThread, rendezvous, block)
	}
}