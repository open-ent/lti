package fr.openent.lti;

import fr.openent.lti.core.PlatformTokens;
import fr.openent.lti.security.KeyManager;
import fr.openent.lti.service.AgsRepository;
import fr.openent.lti.service.Directory;
import fr.openent.lti.service.LinkRepository;
import fr.openent.lti.service.ReplayGuard;
import fr.openent.lti.service.ToolKeys;
import fr.openent.lti.service.ToolRepository;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.EventBus;
import io.vertx.core.json.JsonObject;

/** Dépendances partagées par les contrôleurs du module. */
public class LtiContext {

	public static final String SCORE_PUBLISHED_ADDRESS = "lti.score.published";

	public final Vertx vertx;
	public final EventBus eb;
	/** Identifiant de la plateforme (iss), ex. https://ent.example.org */
	public final String issuer;
	/** URL publique du module, ex. https://ent.example.org/lti */
	public final String baseUrl;
	public final String platformName;
	public final long accessTokenTtl;
	public final KeyManager keys;
	public final PlatformTokens tokens;
	public final ToolRepository tools = new ToolRepository();
	public final LinkRepository links = new LinkRepository();
	public final AgsRepository ags = new AgsRepository();
	public final Directory directory = new Directory();
	public final ToolKeys toolKeys;
	public final ReplayGuard replay;

	public LtiContext(Vertx vertx, EventBus eb, JsonObject config) {
		final JsonObject lti = config.getJsonObject("lti", new JsonObject());
		this.vertx = vertx;
		this.eb = eb;
		this.issuer = stripTrailingSlash(lti.getString("issuer", config.getString("host", "http://localhost:8090")));
		this.baseUrl = issuer + config.getString("app-address", "/lti");
		this.platformName = lti.getString("platform-name", "Open ENT");
		this.accessTokenTtl = lti.getLong("access-token-ttl-seconds", 3600L);
		this.keys = KeyManager.fromConfig(lti);
		this.tokens = new PlatformTokens(keys, issuer);
		this.toolKeys = new ToolKeys(vertx, lti.getLong("jwks-cache-seconds", 600L));
		this.replay = new ReplayGuard(vertx);
	}

	public String tokenEndpoint() {
		return baseUrl + "/token";
	}

	public static long now() {
		return System.currentTimeMillis() / 1000L;
	}

	private static String stripTrailingSlash(String s) {
		return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
	}
}
