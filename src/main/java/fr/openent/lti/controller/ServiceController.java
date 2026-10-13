package fr.openent.lti.controller;

import fr.openent.lti.LtiContext;
import fr.openent.lti.core.Ags;
import fr.openent.lti.core.ClientAssertion;
import fr.openent.lti.core.Lti13;
import fr.openent.lti.core.LtiException;
import fr.openent.lti.core.LtiRoles;
import fr.openent.lti.core.Nrps;
import fr.openent.lti.core.PlatformTokens;
import fr.openent.lti.security.Hashes;
import fr.openent.lti.security.Jwt;
import fr.openent.lti.service.Db;
import fr.openent.lti.service.Directory;
import fr.wseduc.rs.Delete;
import fr.wseduc.rs.Get;
import fr.wseduc.rs.Post;
import fr.wseduc.rs.Put;
import fr.wseduc.webutils.http.BaseController;
import io.vertx.core.Future;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Services LTI Advantage appelés de serveur à serveur par les outils :
 * jeton OAuth2 (client_credentials + private_key_jwt), AGS 2.0 et NRPS 2.0.
 * Aucune session ENT : l'authentification repose sur le jeton Bearer émis par /token.
 */
public class ServiceController extends BaseController {

	private static final int MAX_PAGE = 1000;

	private final LtiContext ctx;

	public ServiceController(LtiContext ctx) {
		this.ctx = ctx;
	}

	// ----------------------------------------------------------------- jeton

	@Post("/token")
	public void token(HttpServerRequest request) {
		Http.form(request).compose(form -> {
			if (!"client_credentials".equals(form.get("grant_type"))) {
				return Async.<JsonObject>fail(400, "unsupported_grant_type");
			}
			if (!Lti13.CLIENT_ASSERTION_TYPE.equals(form.get("client_assertion_type"))) {
				return Async.<JsonObject>fail(400, "invalid_request");
			}
			return Async.attempt(() -> Jwt.decode(form.get("client_assertion"))).compose(jwt -> {
				final String clientId = jwt.payload.getString("iss");
				if (clientId == null) {
					return Async.<JsonObject>fail(401, "invalid_client");
				}
				return ctx.tools.findTool(clientId).compose(tool -> {
					if (tool == null || !tool.getBoolean("enabled", false)) {
						return Async.<JsonObject>fail(401, "invalid_client");
					}
					return ctx.toolKeys.verify(tool, jwt)
							.recover(e -> Async.fail(401, "invalid_client"))
							.compose(v -> Async.attempt(() -> {
								final String jti = ClientAssertion.validate(jwt.payload, clientId, LtiContext.now(),
										ctx.tokenEndpoint(), ctx.issuer);
								if (!ctx.replay.consume("assertion:" + clientId + ":" + jti, 3700)) {
									throw new LtiException(401, "invalid_client");
								}
								final List<String> granted = PlatformTokens.grant(form.get("scope"),
										Db.jsonArray(tool, "scopes"));
								if (granted.isEmpty()) {
									throw new LtiException(400, "invalid_scope");
								}
								return new JsonObject()
										.put("access_token", ctx.tokens.issueAccessToken(clientId, granted,
												LtiContext.now(), ctx.accessTokenTtl))
										.put("token_type", "Bearer")
										.put("expires_in", ctx.accessTokenTtl)
										.put("scope", String.join(" ", granted));
							}));
				});
			});
		}).onSuccess(json -> Http.json(request, 200, "application/json", json))
				.onFailure(e -> Http.error(request, e));
	}

	// ----------------------------------------------------------------- AGS : lineitems

	@Get("/ags/:contextId/lineitems")
	public void listLineItems(HttpServerRequest request) {
		final String contextId = request.params().get("contextId");
		final int limit = Http.intParam(request, "limit", 100, MAX_PAGE);
		final int offset = Http.intParam(request, "offset", 0, Integer.MAX_VALUE);
		authorize(request, contextId, Lti13.SCOPE_LINEITEM, Lti13.SCOPE_LINEITEM_READONLY)
				.compose(tool -> ctx.ags.list(tool.getString("id"), contextId,
						request.params().get("resource_link_id"), request.params().get("resource_id"),
						request.params().get("tag"), limit, offset))
				.onSuccess(rows -> {
					final JsonArray items = new JsonArray();
					for (Object o : rows) {
						final JsonObject row = (JsonObject) o;
						items.add(Ags.lineItemJson(row, lineItemUrl(contextId, row.getValue("id"))));
					}
					if (rows.size() == limit) {
						nextLink(request, lineItemsUrl(contextId), limit, offset + limit);
					}
					Http.json(request, 200, Lti13.MEDIA_LINEITEM_CONTAINER, items);
				})
				.onFailure(e -> Http.error(request, e));
	}

	@Post("/ags/:contextId/lineitems")
	public void createLineItem(HttpServerRequest request) {
		final String contextId = request.params().get("contextId");
		// Le corps est lu avant tout appel asynchrone : la requête n'est pas mise en pause sur ces routes publiques.
		Http.json(request).compose(body -> authorize(request, contextId, Lti13.SCOPE_LINEITEM)
				.compose(tool -> Async.attempt(() -> Ags.validateLineItem(body))
						.compose(item -> checkResourceLink(tool, contextId, item.getString("resourceLinkId"))
								.compose(v -> ctx.ags.create(tool.getString("id"), contextId, item)))))
				.onSuccess(row -> Http.json(request, 201, Lti13.MEDIA_LINEITEM,
						Ags.lineItemJson(row, lineItemUrl(contextId, row.getValue("id")))))
				.onFailure(e -> Http.error(request, e));
	}

	@Get("/ags/:contextId/lineitems/:id")
	public void getLineItem(HttpServerRequest request) {
		final String contextId = request.params().get("contextId");
		authorize(request, contextId, Lti13.SCOPE_LINEITEM, Lti13.SCOPE_LINEITEM_READONLY)
				.compose(tool -> lineItem(request, tool, contextId))
				.onSuccess(row -> Http.json(request, 200, Lti13.MEDIA_LINEITEM,
						Ags.lineItemJson(row, lineItemUrl(contextId, row.getValue("id")))))
				.onFailure(e -> Http.error(request, e));
	}

	@Put("/ags/:contextId/lineitems/:id")
	public void updateLineItem(HttpServerRequest request) {
		final String contextId = request.params().get("contextId");
		Http.json(request).compose(body -> authorize(request, contextId, Lti13.SCOPE_LINEITEM)
				.compose(tool -> lineItem(request, tool, contextId)
						.compose(existing -> Async.attempt(() -> Ags.validateLineItem(body))
								.compose(item -> ctx.ags.update(tool.getString("id"), contextId,
										Long.parseLong(existing.getValue("id").toString()), item)))))
				.onSuccess(row -> Http.json(request, 200, Lti13.MEDIA_LINEITEM,
						Ags.lineItemJson(row, lineItemUrl(contextId, row.getValue("id")))))
				.onFailure(e -> Http.error(request, e));
	}

	@Delete("/ags/:contextId/lineitems/:id")
	public void deleteLineItem(HttpServerRequest request) {
		final String contextId = request.params().get("contextId");
		authorize(request, contextId, Lti13.SCOPE_LINEITEM)
				.compose(tool -> lineItem(request, tool, contextId).compose(row -> ctx.ags.delete(
						tool.getString("id"), contextId, Long.parseLong(row.getValue("id").toString()))))
				.onSuccess(deleted -> Http.noContent(request))
				.onFailure(e -> Http.error(request, e));
	}

	// ----------------------------------------------------------------- AGS : scores et résultats

	@Post("/ags/:contextId/lineitems/:id/scores")
	public void postScore(HttpServerRequest request) {
		final String contextId = request.params().get("contextId");
		Http.json(request).compose(body -> authorize(request, contextId, Lti13.SCOPE_SCORE)
				.compose(tool -> lineItem(request, tool, contextId).compose(row -> Async.attempt(() -> Ags.validateScore(body))
						.compose(score -> ctx.tools.resolveSubject(tool.getString("id"), score.getString("userId"))
								.compose(userId -> Async.require(userId, 400, "unknown.user"))
								.compose(userId -> ctx.directory.isMember(contextId, userId)
										.compose(member -> member ? Future.succeededFuture(userId)
												: Async.<String>fail(400, "user.not.in.context")))
								.compose(userId -> ctx.ags.upsertScore(Long.parseLong(row.getValue("id").toString()),
										userId, score).map(applied -> {
									if (applied && "FullyGraded".equals(score.getString("gradingProgress"))) {
										publishScore(tool, contextId, row, userId, score);
									}
									return applied;
								}))))))
				.onSuccess(applied -> Http.noContent(request))
				.onFailure(e -> Http.error(request, e));
	}

	@Get("/ags/:contextId/lineitems/:id/results")
	public void listResults(HttpServerRequest request) {
		final String contextId = request.params().get("contextId");
		final int limit = Http.intParam(request, "limit", 100, MAX_PAGE);
		final int offset = Http.intParam(request, "offset", 0, Integer.MAX_VALUE);
		authorize(request, contextId, Lti13.SCOPE_RESULT_READONLY)
				.compose(tool -> lineItem(request, tool, contextId).compose(row -> ctx.ags.results(
						tool.getString("id"), Long.parseLong(row.getValue("id").toString()),
						request.params().get("user_id"), limit, offset).map(results -> {
					final String url = lineItemUrl(contextId, row.getValue("id"));
					final JsonArray out = new JsonArray();
					for (Object o : results) {
						final JsonObject result = (JsonObject) o;
						out.add(Ags.resultJson(result, url, result.getString("sub")));
					}
					if (results.size() == limit) {
						nextLink(request, url + "/results", limit, offset + limit);
					}
					return out;
				})))
				.onSuccess(results -> Http.json(request, 200, Lti13.MEDIA_RESULT_CONTAINER, results))
				.onFailure(e -> Http.error(request, e));
	}

	/** Diffusion sur le bus pour les modules de notes (ex. competences). Note ramenée au barème de la colonne. */
	private void publishScore(JsonObject tool, String contextId, JsonObject lineItem, String userId, JsonObject score) {
		final double maximum = Double.parseDouble(lineItem.getValue("score_maximum").toString());
		ctx.eb.publish(LtiContext.SCORE_PUBLISHED_ADDRESS, new JsonObject()
				.put("toolId", tool.getString("id"))
				.put("toolName", tool.getString("name"))
				.put("contextId", contextId)
				.put("lineItemId", lineItem.getValue("id"))
				.put("label", lineItem.getString("label"))
				.put("resourceLinkId", lineItem.getString("resource_link_id"))
				.put("userId", userId)
				.put("score", Ags.normalized(score, maximum))
				.put("scoreMaximum", maximum)
				.put("comment", score.getString("comment"))
				.put("timestamp", score.getString("timestamp")));
	}

	// ----------------------------------------------------------------- NRPS

	@Get("/nrps/:contextId/memberships")
	public void memberships(HttpServerRequest request) {
		final String contextId = request.params().get("contextId");
		final String role = request.params().get("role");
		final int limit = Http.intParam(request, "limit", 500, MAX_PAGE);
		final int offset = Http.intParam(request, "offset", 0, Integer.MAX_VALUE);
		authorize(request, contextId, Lti13.SCOPE_NRPS)
				.compose(tool -> checkResourceLink(tool, contextId, request.params().get("rlid"))
						.compose(v -> ctx.directory.context(contextId))
						.compose(context -> Async.require(context, 404, "unknown.context"))
						.compose(context -> ctx.directory.members(contextId).compose(rows -> {
							final String salt = tool.getString("subject_salt");
							final Map<String, String> subjects = new HashMap<>();
							final List<JsonObject> members = new ArrayList<>();
							for (Object o : rows) {
								final JsonObject row = (JsonObject) o;
								final String sub = Hashes.pseudonym(salt, row.getString("id"));
								subjects.put(sub, row.getString("id"));
								final JsonObject member = Nrps.member(row, sub, tool.getBoolean("share_name", false),
										tool.getBoolean("share_email", false));
								if (LtiRoles.matches(member.getJsonArray("roles").getString(0), role)) {
									members.add(member);
								}
							}
							members.sort((a, b) -> a.getString("user_id").compareTo(b.getString("user_id")));
							final String url = ctx.baseUrl + "/nrps/" + contextId + "/memberships";
							if (offset + limit < members.size()) {
								nextLink(request, url, limit, offset + limit);
							}
							final JsonObject container = Nrps.container(url, new JsonObject()
											.put("id", contextId)
											.put("label", context.getString("name"))
											.put("title", context.getString("name")),
									Directory.page(new JsonArray(new ArrayList<Object>(members)), offset, limit));
							return ctx.tools.registerSubjects(tool.getString("id"), subjects).map(v -> container);
						})))
				.onSuccess(container -> Http.json(request, 200, Lti13.MEDIA_MEMBERSHIP_CONTAINER, container))
				.onFailure(e -> Http.error(request, e));
	}

	// ----------------------------------------------------------------- utilitaires

	/** Jeton valide pour l'un des scopes, outil actif, et contexte dans lequel l'outil a été lancé. */
	private Future<JsonObject> authorize(HttpServerRequest request, String contextId, String... scopes) {
		return Async.attempt(() -> ctx.tokens.verifyAccessToken(request.headers().get("Authorization"),
				LtiContext.now(), scopes))
				.compose(ctx.tools::findTool)
				.compose(tool -> tool != null && tool.getBoolean("enabled", false)
						? ctx.tools.isContextRegistered(tool.getString("id"), contextId)
								.compose(known -> known ? Future.succeededFuture(tool)
										: Async.<JsonObject>fail(404, "unknown.context"))
						: Async.<JsonObject>fail(401, "invalid_token"));
	}

	private Future<JsonObject> lineItem(HttpServerRequest request, JsonObject tool, String contextId) {
		final long id;
		try {
			id = Long.parseLong(request.params().get("id"));
		} catch (NumberFormatException e) {
			return Async.fail(404, "unknown.lineitem");
		}
		return ctx.ags.find(tool.getString("id"), contextId, id)
				.compose(row -> Async.require(row, 404, "unknown.lineitem"));
	}

	private Future<Void> checkResourceLink(JsonObject tool, String contextId, String resourceLinkId) {
		if (resourceLinkId == null) {
			return Future.succeededFuture();
		}
		return ctx.links.find(resourceLinkId).compose(link -> link != null
				&& tool.getString("id").equals(link.getString("tool_id"))
				&& contextId.equals(link.getString("context_id"))
				? Future.succeededFuture() : Async.<Void>fail(400, "unknown.resource.link"));
	}

	private String lineItemsUrl(String contextId) {
		return ctx.baseUrl + "/ags/" + contextId + "/lineitems";
	}

	private String lineItemUrl(String contextId, Object id) {
		return lineItemsUrl(contextId) + "/" + id;
	}

	private static void nextLink(HttpServerRequest request, String url, int limit, int offset) {
		request.response().putHeader("Link", "<" + url + "?limit=" + limit + "&offset=" + offset + ">; rel=\"next\"");
	}
}
