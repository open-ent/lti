package fr.openent.lti.core;

import fr.openent.lti.security.Jwt;
import io.vertx.core.json.JsonObject;

/**
 * Validation des claims d'une client_assertion JWT (RFC 7523) présentée par un outil
 * au point de terminaison de jeton. La signature est vérifiée séparément avec la JWKS de l'outil.
 */
public final class ClientAssertion {

	private ClientAssertion() {
	}

	/** Retourne le jti de l'assertion, à consommer une seule fois (anti-rejeu). */
	public static String validate(JsonObject payload, String clientId, long nowSeconds, String... acceptedAudiences)
			throws LtiException {
		if (!clientId.equals(payload.getString("iss")) || !clientId.equals(payload.getString("sub"))) {
			throw new LtiException(401, "invalid_client");
		}
		boolean audienceOk = false;
		for (String audience : acceptedAudiences) {
			audienceOk |= Jwt.audienceContains(payload, audience);
		}
		if (!audienceOk) {
			throw new LtiException(401, "invalid_client");
		}
		Jwt.checkTimes(payload, nowSeconds, 60);
		if (payload.getLong("exp") > nowSeconds + 3600) {
			throw new LtiException(401, "invalid_client");
		}
		final String jti = payload.getString("jti");
		if (jti == null || jti.isEmpty()) {
			throw new LtiException(401, "invalid_client");
		}
		return jti;
	}
}
