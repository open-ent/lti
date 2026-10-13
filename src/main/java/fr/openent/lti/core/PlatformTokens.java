package fr.openent.lti.core;

import fr.openent.lti.security.Hashes;
import fr.openent.lti.security.Jwt;
import fr.openent.lti.security.KeyManager;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Jetons signés par la plateforme pour elle-même :
 * <ul>
 *   <li>lti_message_hint : contexte du lancement transporté par l'outil entre /launch et /auth ;</li>
 *   <li>data Deep Linking : contexte de la demande, renvoyé tel quel par l'outil ;</li>
 *   <li>jeton d'accès OAuth2 aux services AGS / NRPS.</li>
 * </ul>
 * Chaque jeton porte un « typ » distinct pour qu'un type ne puisse pas être rejoué à la place d'un autre.
 */
public class PlatformTokens {

	public static final String TYP_MESSAGE_HINT = "lti-message-hint";
	public static final String TYP_DEEP_LINK_DATA = "lti-dl-data";
	public static final String TYP_ACCESS_TOKEN = "lti-access-token";
	private static final long LEEWAY = 60;

	private final KeyManager keys;
	private final String issuer;

	public PlatformTokens(KeyManager keys, String issuer) {
		this.keys = keys;
		this.issuer = issuer;
	}

	public String issue(String typ, JsonObject claims, long nowSeconds, long ttlSeconds) {
		final JsonObject payload = claims.copy()
				.put("iss", issuer)
				.put("aud", issuer)
				.put("typ", typ)
				.put("iat", nowSeconds)
				.put("exp", nowSeconds + ttlSeconds)
				.put("jti", Hashes.randomHex(16));
		return keys.sign(payload);
	}

	public JsonObject verify(String typ, String token, long nowSeconds) throws LtiException {
		final Jwt.Decoded decoded = Jwt.decode(token);
		Jwt.verify(decoded, keys.getPublicKey());
		Jwt.checkTimes(decoded.payload, nowSeconds, LEEWAY);
		if (!typ.equals(decoded.payload.getString("typ")) || !issuer.equals(decoded.payload.getString("iss"))) {
			throw new LtiException(401, "invalid.token.type");
		}
		return decoded.payload;
	}

	public String issueAccessToken(String toolId, List<String> scopes, long nowSeconds, long ttlSeconds) {
		return issue(TYP_ACCESS_TOKEN, new JsonObject()
				.put("sub", toolId)
				.put("scope", String.join(" ", scopes)), nowSeconds, ttlSeconds);
	}

	/** Vérifie un jeton Bearer et l'existence d'au moins un des scopes acceptés. Retourne l'id de l'outil. */
	public String verifyAccessToken(String authorizationHeader, long nowSeconds, String... acceptedScopes) throws LtiException {
		if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
			throw new LtiException(401, "missing.bearer.token");
		}
		final JsonObject payload = verify(TYP_ACCESS_TOKEN, authorizationHeader.substring(7).trim(), nowSeconds);
		final List<String> granted = splitScopes(payload.getString("scope"));
		for (String scope : acceptedScopes) {
			if (granted.contains(scope)) {
				return payload.getString("sub");
			}
		}
		throw new LtiException(403, "insufficient.scope");
	}

	public static List<String> splitScopes(String scope) {
		final List<String> scopes = new ArrayList<>();
		if (scope != null) {
			for (String s : scope.trim().split("\\s+")) {
				if (!s.isEmpty()) {
					scopes.add(s);
				}
			}
		}
		return scopes;
	}

	/** Intersection entre scopes demandés et scopes autorisés pour l'outil. */
	public static List<String> grant(String requested, JsonArray allowed) {
		final List<String> granted = new ArrayList<>();
		for (String s : splitScopes(requested)) {
			if (allowed != null && allowed.contains(s) && !granted.contains(s)) {
				granted.add(s);
			}
		}
		return granted;
	}
}
