package org.bread_experts_group.acme_microserver.handler

import org.bread_experts_group.MultipleArgs
import org.bread_experts_group.SingleArgs
import org.bread_experts_group.ACMEAuthorization
import org.bread_experts_group.ACMEChallenge
import org.bread_experts_group.jws.JSONWebKey
import java.io.File
import java.security.KeyPair
import java.util.concurrent.CountDownLatch
import java.util.logging.Logger

@FunctionalInterface
interface ACMEChallengeHandler {
	fun identifier(): String
	fun defaultPreference(): Int
	fun handle(
		singleArgs: SingleArgs,
		multipleArgs: MultipleArgs,
		jwsKeyPair: KeyPair,
		jsonWebKey: JSONWebKey,
		authorization: ACMEAuthorization,
		challenge: ACMEChallenge,
		localFileBase: File,
		authLogger: Logger
	): Triple<Thread, CountDownLatch, CountDownLatch>
}