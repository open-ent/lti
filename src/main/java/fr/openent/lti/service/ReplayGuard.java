package fr.openent.lti.service;

import io.vertx.core.Vertx;
import io.vertx.core.shareddata.LocalMap;

/**
 * Anti-rejeu des valeurs à usage unique (nonce OIDC, jti des assertions et des lti_message_hint).
 * Stockage en mémoire partagée de la JVM : avec plusieurs instances du module derrière un
 * répartiteur, prévoir l'affinité de session ou une implémentation Redis.
 */
public class ReplayGuard {

	private final LocalMap<String, Long> seen;

	public ReplayGuard(Vertx vertx) {
		this.seen = vertx.sharedData().getLocalMap("lti.replay-guard");
		vertx.setPeriodic(60_000L, id -> purge());
	}

	/** @return true à la première utilisation de la clé, false si déjà vue et non expirée. */
	public boolean consume(String key, long ttlSeconds) {
		final long now = System.currentTimeMillis();
		final long expiry = now + ttlSeconds * 1000L;
		final Long previous = seen.putIfAbsent(key, expiry);
		if (previous == null) {
			return true;
		}
		return previous < now && seen.replace(key, previous, expiry);
	}

	private void purge() {
		final long now = System.currentTimeMillis();
		for (String key : seen.keySet()) {
			final Long expiry = seen.get(key);
			if (expiry != null && expiry < now) {
				seen.removeIfPresent(key, expiry);
			}
		}
	}
}
