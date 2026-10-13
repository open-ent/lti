package fr.openent.lti.service;

import fr.openent.lti.core.LtiException;
import fr.openent.lti.security.Jwk;
import fr.openent.lti.security.Jwt;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.JsonObject;

import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Vérification des JWT émis par un outil : clé publique fixe ou JWKS distant (mis en cache). */
public class ToolKeys {

	private final HttpClient client;
	private final long cacheMillis;
	private final Map<String, CachedJwks> cache = new ConcurrentHashMap<>();

	public ToolKeys(Vertx vertx, long cacheSeconds) {
		this.client = vertx.createHttpClient(new HttpClientOptions()
				.setConnectTimeout(5000).setIdleTimeout(10).setTrustAll(false));
		this.cacheMillis = cacheSeconds * 1000L;
	}

	/** Vérifie la signature du JWT avec la clé de l'outil. */
	public Future<Void> verify(JsonObject tool, Jwt.Decoded jwt) {
		final JsonObject publicJwk = Db.jsonObject(tool, "public_jwk");
		if (publicJwk != null) {
			return attempt(publicJwk.containsKey("keys") ? publicJwk : new JsonObject()
					.put("keys", new io.vertx.core.json.JsonArray().add(publicJwk)), jwt);
		}
		final String url = tool.getString("jwks_url");
		final CachedJwks cached = cache.get(url);
		if (cached != null && cached.expiry > System.currentTimeMillis()) {
			// kid inconnu : l'outil a pu changer de clé ; rechargement limité à une fois par minute.
			return attempt(cached.jwks, jwt).recover(e -> "unknown.jwk.kid".equals(e.getMessage())
					&& cached.fetchedAt + 60_000L < System.currentTimeMillis()
					? fetch(url).compose(jwks -> attempt(jwks, jwt))
					: Future.failedFuture(e));
		}
		return fetch(url).compose(jwks -> attempt(jwks, jwt));
	}

	private Future<Void> attempt(JsonObject jwks, Jwt.Decoded jwt) {
		try {
			final PublicKey key = Jwk.toPublicKey(Jwk.select(jwks, jwt.kid()));
			Jwt.verify(jwt, key);
			return Future.succeededFuture();
		} catch (LtiException e) {
			return Future.failedFuture(e);
		}
	}

	private Future<JsonObject> fetch(String url) {
		return client.request(new RequestOptions().setMethod(HttpMethod.GET).setAbsoluteURI(url).setTimeout(10_000))
				.compose(request -> request.send())
				.compose(response -> response.statusCode() == 200
						? response.body()
						: Future.failedFuture(new LtiException(401, "jwks.unavailable")))
				.map(body -> {
					final JsonObject jwks = new JsonObject(body);
					final long now = System.currentTimeMillis();
					cache.put(url, new CachedJwks(jwks, now, now + cacheMillis));
					return jwks;
				});
	}

	private static final class CachedJwks {
		private final JsonObject jwks;
		private final long fetchedAt;
		private final long expiry;

		private CachedJwks(JsonObject jwks, long fetchedAt, long expiry) {
			this.jwks = jwks;
			this.fetchedAt = fetchedAt;
			this.expiry = expiry;
		}
	}
}
