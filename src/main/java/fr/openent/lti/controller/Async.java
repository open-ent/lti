package fr.openent.lti.controller;

import fr.openent.lti.core.LtiException;
import io.vertx.core.Future;

/** Passage des contrôles levant LtiException dans les chaînes de Future. */
final class Async {

	interface Check<T> {
		T get() throws LtiException;
	}

	private Async() {
	}

	static <T> Future<T> attempt(Check<T> check) {
		try {
			return Future.succeededFuture(check.get());
		} catch (LtiException e) {
			return Future.failedFuture(e);
		}
	}

	static <T> Future<T> fail(int status, String message) {
		return Future.failedFuture(new LtiException(status, message));
	}

	static <T> Future<T> require(T value, int status, String message) {
		return value == null ? fail(status, message) : Future.succeededFuture(value);
	}
}
