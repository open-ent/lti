package fr.openent.lti.controller;

import fr.openent.lti.LtiContext;
import fr.openent.lti.core.DeepLinkResponse;
import fr.openent.lti.core.Html;
import fr.openent.lti.core.LaunchRequest;
import fr.openent.lti.core.Lti13;
import fr.openent.lti.core.LtiException;
import fr.openent.lti.core.LtiRoles;
import fr.openent.lti.core.PlatformTokens;
import fr.openent.lti.security.Hashes;
import fr.openent.lti.security.Jwt;
import fr.openent.lti.service.Db;
import fr.wseduc.rs.Delete;
import fr.wseduc.rs.Get;
import fr.wseduc.rs.Post;
import fr.wseduc.security.ActionType;
import fr.wseduc.security.SecuredAction;
import fr.wseduc.webutils.http.BaseController;
import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.entcore.common.user.DefaultFunctions;
import org.entcore.common.user.UserInfos;
import org.entcore.common.user.UserUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parcours navigateur LTI 1.3 : liste des outils, lancement (OIDC third-party initiated login),
 * point d'autorisation, Deep Linking 2.0, et publication des clés de la plateforme.
 */
public class PlatformController extends BaseController {

	private static final long HINT_TTL = 300;
	private static final long DEEP_LINK_DATA_TTL = 3600;

	private final LtiContext ctx;

	public PlatformController(LtiContext ctx) {
		this.ctx = ctx;
	}

	// ----------------------------------------------------------------- découverte

	@Get("/.well-known/jwks.json")
	public void jwks(HttpServerRequest request) {
		Http.json(request, 200, "application/json", ctx.keys.jwks());
	}

	@Get("/.well-known/openid-configuration")
	public void openidConfiguration(HttpServerRequest request) {
		Http.json(request, 200, "application/json", new JsonObject()
				.put("issuer", ctx.issuer)
				.put("authorization_endpoint", ctx.baseUrl + "/auth")
				.put("token_endpoint", ctx.tokenEndpoint())
				.put("token_endpoint_auth_methods_supported", new JsonArray().add("private_key_jwt"))
				.put("token_endpoint_auth_signing_alg_values_supported", new JsonArray().add(Jwt.RS256))
				.put("jwks_uri", ctx.baseUrl + "/.well-known/jwks.json")
				.put("scopes_supported", new JsonArray().add("openid")
						.add(Lti13.SCOPE_LINEITEM).add(Lti13.SCOPE_LINEITEM_READONLY)
						.add(Lti13.SCOPE_RESULT_READONLY).add(Lti13.SCOPE_SCORE).add(Lti13.SCOPE_NRPS))
				.put("response_types_supported", new JsonArray().add("id_token"))
				.put("subject_types_supported", new JsonArray().add("pairwise"))
				.put("id_token_signing_alg_values_supported", new JsonArray().add(Jwt.RS256))
				.put("claims_supported", new JsonArray().add("iss").add("aud").add("sub").add("iat").add("exp")
						.add("nonce").add("given_name").add("family_name").add("name").add("email").add("locale"))
				.put("https://purl.imsglobal.org/spec/lti-platform-configuration", new JsonObject()
						.put("product_family_code", "open-ent")
						.put("messages_supported", new JsonArray()
								.add(new JsonObject().put("type", Lti13.MSG_RESOURCE_LINK))
								.add(new JsonObject().put("type", Lti13.MSG_DEEP_LINKING)))));
	}

	// ----------------------------------------------------------------- outils de l'utilisateur

	@Get("/tools")
	@SecuredAction(value = "", type = ActionType.AUTHENTICATED)
	public void listTools(HttpServerRequest request) {
		UserUtils.getUserInfos(eb, request, user -> {
			if (user == null) {
				unauthorized(request);
				return;
			}
			ctx.tools.toolsForStructures(user.getStructures())
					.onSuccess(tools -> renderJson(request, tools))
					.onFailure(e -> Http.error(request, e));
		});
	}

	// ----------------------------------------------------------------- lancement

	/** Lance un outil : ?context=<classe|groupe> et/ou ?resourceLink=<id d'un lien Deep Linking>. */
	@Get("/launch/:toolId")
	@SecuredAction("lti.launch")
	public void launch(HttpServerRequest request) {
		UserUtils.getUserInfos(eb, request, user -> {
			if (user == null) {
				unauthorized(request);
				return;
			}
			final String toolId = request.params().get("toolId");
			final String resourceLinkId = request.params().get("resourceLink");
			final Future<JsonObject> linkFuture = resourceLinkId == null
					? Future.succeededFuture(null)
					: ctx.links.find(resourceLinkId).compose(link ->
							link != null && toolId.equals(link.getString("tool_id"))
									? Future.succeededFuture(link)
									: Async.<JsonObject>fail(404, "unknown.resource.link"));
			linkFuture.compose(link -> {
				final String contextId = link != null && link.getString("context_id") != null
						? link.getString("context_id") : request.params().get("context");
				return checkContextAccess(user, contextId)
						.compose(v -> enabledTool(toolId))
						.compose(tool -> deploymentFor(user, toolId, link))
						.map(deployment -> {
							final JsonObject hint = new JsonObject()
									.put("user", user.getUserId())
									.put("tool", toolId)
									.put("deployment", deployment.getString("id"))
									.put("msg", Lti13.MSG_RESOURCE_LINK)
									.put("context", contextId)
									.put("link", link != null ? link.getString("id")
											: "placement:" + toolId + ":" + (contextId != null ? contextId : deployment.getString("id")));
							return hint;
						});
			}).compose(hint -> enabledTool(toolId).map(tool -> initiationUrl(tool, hint,
					tool.getString("target_link_uri"))))
					.onSuccess(url -> redirectTo(request, url))
					.onFailure(e -> Http.htmlError(request, e));
		});
	}

	/** Demande de sélection de contenu (Deep Linking) : ?context=<classe|groupe>&target=<type>&targetId=<id>. */
	@Get("/deeplink/:toolId")
	@SecuredAction("lti.deeplink")
	public void deepLink(HttpServerRequest request) {
		UserUtils.getUserInfos(eb, request, user -> {
			if (user == null) {
				unauthorized(request);
				return;
			}
			final String toolId = request.params().get("toolId");
			final String contextId = request.params().get("context");
			if (contextId == null) {
				Http.htmlError(request, new LtiException("missing.context"));
				return;
			}
			checkContextAccess(user, contextId)
					.compose(v -> enabledTool(toolId))
					.compose(tool -> tool.getString("deep_linking_url") == null
							? Async.<String>fail(400, "tool.without.deep.linking")
							: deploymentFor(user, toolId, null).map(deployment -> initiationUrl(tool, new JsonObject()
									.put("user", user.getUserId())
									.put("tool", toolId)
									.put("deployment", deployment.getString("id"))
									.put("msg", Lti13.MSG_DEEP_LINKING)
									.put("context", contextId)
									.put("target", request.params().get("target"))
									.put("targetId", request.params().get("targetId")),
									tool.getString("deep_linking_url"))))
					.onSuccess(url -> redirectTo(request, url))
					.onFailure(e -> Http.htmlError(request, e));
		});
	}

	// ----------------------------------------------------------------- point d'autorisation OIDC

	@Get("/auth")
	public void authorizeGet(HttpServerRequest request) {
		authorize(request, null);
	}

	@Post("/auth")
	public void authorizePost(HttpServerRequest request) {
		Http.form(request)
				.onSuccess(form -> authorize(request, form))
				.onFailure(e -> Http.htmlError(request, e));
	}

	/**
	 * Réponse à la demande d'authentification de l'outil (OIDC implicit flow, form_post).
	 * L'utilisateur est celui du lti_message_hint signé par la plateforme, à usage unique et de courte durée ;
	 * le cookie de session ENT (SameSite=Strict) n'est en général pas transmis sur ce rappel inter-sites.
	 * S'il l'est, il doit désigner le même utilisateur.
	 */
	private void authorize(HttpServerRequest request, MultiMap form) {
		final String clientId = Http.param(request, form, "client_id");
		final String redirectUri = Http.param(request, form, "redirect_uri");
		final String state = Http.param(request, form, "state");
		final String nonce = Http.param(request, form, "nonce");

		Async.attempt(() -> {
			if (!"openid".equals(Http.param(request, form, "scope"))) {
				throw new LtiException("invalid_scope");
			}
			if (!"id_token".equals(Http.param(request, form, "response_type"))) {
				throw new LtiException("unsupported_response_type");
			}
			final String responseMode = Http.param(request, form, "response_mode");
			final String prompt = Http.param(request, form, "prompt");
			if (!"form_post".equals(responseMode) || (prompt != null && !"none".equals(prompt))) {
				throw new LtiException("invalid_request");
			}
			if (clientId == null || redirectUri == null || nonce == null || nonce.isEmpty()) {
				throw new LtiException("invalid_request");
			}
			final JsonObject hint = ctx.tokens.verify(PlatformTokens.TYP_MESSAGE_HINT,
					Http.param(request, form, "lti_message_hint"), LtiContext.now());
			if (!clientId.equals(hint.getString("tool"))
					|| !hint.getString("user").equals(Http.param(request, form, "login_hint"))) {
				throw new LtiException("invalid_request");
			}
			if (!ctx.replay.consume("hint:" + hint.getString("jti"), HINT_TTL * 2)
					|| !ctx.replay.consume("nonce:" + clientId + ":" + nonce, HINT_TTL * 2)) {
				throw new LtiException("replayed_request");
			}
			return hint;
		}).compose(hint -> enabledTool(clientId).compose(tool -> {
			if (!Db.jsonArray(tool, "redirect_uris").contains(redirectUri)) {
				return Async.fail(400, "invalid_redirect_uri");
			}
			return launchUser(request, hint.getString("user"))
					.compose(user -> buildIdToken(request, tool, hint, user, nonce));
		})).onSuccess(idToken -> {
			final Map<String, String> fields = new LinkedHashMap<>();
			fields.put("id_token", idToken);
			fields.put("state", state);
			Http.html(request, 200, Html.autoPostForm(redirectUri, fields));
		}).onFailure(e -> Http.htmlError(request, e));
	}

	private Future<UserInfos> launchUser(HttpServerRequest request, String userId) {
		final Promise<UserInfos> promise = Promise.promise();
		UserUtils.getUserInfos(eb, request, sessionUser -> {
			if (sessionUser != null) {
				if (userId.equals(sessionUser.getUserId())) {
					promise.complete(sessionUser);
				} else {
					promise.fail(new LtiException(403, "login_required"));
				}
				return;
			}
			UserUtils.getUserInfos(eb, userId, user -> {
				if (user == null) {
					promise.fail(new LtiException(403, "login_required"));
				} else {
					promise.complete(user);
				}
			});
		});
		return promise.future();
	}

	private Future<String> buildIdToken(HttpServerRequest request, JsonObject tool, JsonObject hint, UserInfos user,
			String nonce) {
		final String toolId = tool.getString("id");
		final String contextId = hint.getString("context");
		final String messageType = hint.getString("msg");
		final String salt = tool.getString("subject_salt");
		final String linkId = hint.getString("link");

		final Future<JsonObject> contextFuture = contextId == null ? Future.succeededFuture(null)
				: ctx.directory.context(contextId).compose(c -> Async.require(c, 404, "unknown.context"));
		final Future<JsonObject> linkFuture = linkId == null || linkId.startsWith("placement:")
				? Future.succeededFuture(null) : ctx.links.find(linkId);

		return contextFuture.compose(context -> linkFuture.compose(link -> {
			final Future<JsonObject> lineItemFuture = link == null
					? Future.succeededFuture(null) : ctx.ags.findByResourceLink(link.getString("id"));
			return lineItemFuture.compose(lineItem -> {
				final Map<String, String> subjects = new HashMap<>();
				final String sub = Hashes.pseudonym(salt, user.getUserId());
				subjects.put(sub, user.getUserId());

				final LaunchRequest launch = new LaunchRequest();
				launch.issuer = ctx.issuer;
				launch.clientId = toolId;
				launch.deploymentId = hint.getString("deployment");
				launch.subject = sub;
				launch.nonce = nonce;
				launch.messageType = messageType;
				launch.issuedAt = LtiContext.now();
				launch.platformGuid = ctx.issuer;
				launch.platformName = ctx.platformName;
				launch.documentTarget = tool.getString("document_target", "window");
				launch.returnUrl = ctx.issuer + "/";
				launch.locale = locale(request);
				launch.roles = LtiRoles.launchRoles(user.getType(), isAdministrator(user));
				if ("Relative".equals(user.getType()) && user.getChildrenIds() != null) {
					final List<String> scope = new ArrayList<>();
					for (String childId : user.getChildrenIds()) {
						final String childSub = Hashes.pseudonym(salt, childId);
						scope.add(childSub);
						subjects.put(childSub, childId);
					}
					launch.mentorScope = scope;
				}
				if (tool.getBoolean("share_name", false)) {
					launch.givenName = user.getFirstName();
					launch.familyName = user.getLastName();
					launch.name = user.getUsername();
				}
				if (tool.getBoolean("share_email", false)) {
					launch.email = user.getEmail();
				}
				final JsonObject custom = Db.jsonObject(tool, "custom");
				launch.custom = custom == null ? new JsonObject() : custom.copy();
				if (context != null) {
					launch.contextId = contextId;
					launch.contextLabel = context.getString("name");
					launch.contextTitle = context.getString("name");
					addServices(launch, tool, contextId, lineItem);
				}

				if (Lti13.MSG_DEEP_LINKING.equals(messageType)) {
					launch.targetLinkUri = tool.getString("deep_linking_url");
					final String data = ctx.tokens.issue(PlatformTokens.TYP_DEEP_LINK_DATA, new JsonObject()
							.put("tool", toolId)
							.put("deployment", hint.getString("deployment"))
							.put("user", user.getUserId())
							.put("context", contextId)
							.put("target", hint.getString("target"))
							.put("targetId", hint.getString("targetId")), LtiContext.now(), DEEP_LINK_DATA_TTL);
					launch.deepLinkingSettings = LaunchRequest.deepLinkingSettings(ctx.baseUrl + "/deeplink/return", data);
				} else {
					launch.resourceLinkId = linkId;
					if (link != null) {
						launch.resourceLinkTitle = link.getString("title");
						if (link.getString("url") != null) {
							launch.targetLinkUri = link.getString("url");
						}
						final JsonObject linkCustom = Db.jsonObject(link, "custom");
						if (linkCustom != null) {
							launch.custom.mergeIn(linkCustom);
						}
					}
					if (launch.targetLinkUri == null) {
						launch.targetLinkUri = tool.getString("target_link_uri");
					}
				}

				final Future<Void> registered = contextId == null ? Future.succeededFuture()
						: ctx.tools.registerContext(toolId, contextId, hint.getString("deployment"));
				return registered
						.compose(v -> ctx.tools.registerSubjects(toolId, subjects))
						.map(v -> ctx.keys.sign(launch.toClaims()));
			});
		}));
	}

	private void addServices(LaunchRequest launch, JsonObject tool, String contextId, JsonObject lineItem) {
		final JsonArray scopes = Db.jsonArray(tool, "scopes");
		final JsonArray agsScopes = new JsonArray();
		for (String scope : new String[]{Lti13.SCOPE_LINEITEM, Lti13.SCOPE_LINEITEM_READONLY,
				Lti13.SCOPE_RESULT_READONLY, Lti13.SCOPE_SCORE}) {
			if (scopes.contains(scope)) {
				agsScopes.add(scope);
			}
		}
		if (!agsScopes.isEmpty()) {
			final String lineItems = ctx.baseUrl + "/ags/" + contextId + "/lineitems";
			final JsonObject endpoint = new JsonObject().put("scope", agsScopes).put("lineitems", lineItems);
			if (lineItem != null) {
				endpoint.put("lineitem", lineItems + "/" + lineItem.getValue("id"));
			}
			launch.agsEndpoint = endpoint;
		}
		if (scopes.contains(Lti13.SCOPE_NRPS)) {
			launch.nrpsMembershipsUrl = ctx.baseUrl + "/nrps/" + contextId + "/memberships";
		}
	}

	// ----------------------------------------------------------------- retour Deep Linking

	@Post("/deeplink/return")
	public void deepLinkReturn(HttpServerRequest request) {
		Http.form(request)
				.compose(form -> Async.attempt(() -> Jwt.decode(form.get("JWT"))))
				.compose(jwt -> {
					final String clientId = jwt.payload.getString("iss");
					return clientId == null ? Async.fail(401, "invalid.issuer") : enabledTool(clientId)
							.compose(tool -> ctx.toolKeys.verify(tool, jwt)
									.compose(v -> Async.attempt(() -> {
										Jwt.checkTimes(jwt.payload, LtiContext.now(), 60);
										final String nonce = jwt.payload.getString("nonce");
										if (nonce == null || !ctx.replay.consume("dl:" + clientId + ":" + nonce, 3600)) {
											throw new LtiException("replayed_request");
										}
										final String rawData = jwt.payload.getString(Lti13.CLAIM_DL_DATA);
										final JsonObject data = ctx.tokens.verify(PlatformTokens.TYP_DEEP_LINK_DATA,
												rawData, LtiContext.now());
										if (!clientId.equals(data.getString("tool"))) {
											throw new LtiException(401, "invalid.deep.linking.data");
										}
										return new Object[]{data, DeepLinkResponse.parse(jwt.payload, clientId,
												ctx.issuer, data.getString("deployment"), rawData)};
									}))
									.compose(parsed -> saveContentItems(clientId, (JsonObject) parsed[0],
											(DeepLinkResponse) parsed[1])));
				})
				.onSuccess(page -> Http.html(request, 200, page))
				.onFailure(e -> Http.htmlError(request, e));
	}

	private Future<String> saveContentItems(String toolId, JsonObject data, DeepLinkResponse response) {
		final String contextId = data.getString("context");
		final JsonArray created = new JsonArray();
		Future<Void> chain = Future.succeededFuture();
		for (JsonObject item : response.items) {
			chain = chain.compose(v -> ctx.links.create(toolId, data.getString("deployment"), contextId,
					data.getString("target"), data.getString("targetId"), item, data.getString("user"))
					.compose(link -> {
						created.add(new JsonObject()
								.put("id", link.getString("id"))
								.put("type", link.getString("type"))
								.put("title", link.getString("title"))
								.put("launchUrl", ctx.baseUrl + "/launch/" + toolId + "?resourceLink=" + link.getString("id")));
						final JsonObject lineItem = item.getJsonObject("lineItem");
						if (lineItem == null || contextId == null) {
							return Future.succeededFuture();
						}
						return ctx.ags.create(toolId, contextId, lineItem.copy()
								.put("resourceLinkId", link.getString("id"))).mapEmpty();
					}));
		}
		return chain.map(v -> deepLinkResultPage(created, response));
	}

	private String deepLinkResultPage(JsonArray created, DeepLinkResponse response) {
		final StringBuilder list = new StringBuilder("<ul>");
		for (Object o : created) {
			list.append("<li>").append(Html.escape(((JsonObject) o).getString("title"))).append("</li>");
		}
		list.append("</ul>");
		final String message = response.errorMessage != null ? response.errorMessage
				: response.message != null ? response.message : created.size() + " élément(s) ajouté(s).";
		// Les données sont transmises à la fenêtre ENT qui a ouvert la sélection (même origine que l'issuer).
		final String payload = new JsonObject().put("type", "lti:deeplink").put("items", created).encode()
				.replace("<", "\\u003c");
		return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>LTI</title></head><body>"
				+ "<p>" + Html.escape(message) + "</p>" + list
				+ "<script>(function(){var w=window.opener||(window.parent!==window?window.parent:null);"
				+ "if(w){w.postMessage(" + payload + "," + Json.encode(ctx.issuer).replace("<", "\\u003c")
				+ ");}})();</script>"
				+ "</body></html>";
	}

	// ----------------------------------------------------------------- liens de ressource

	@Get("/resource-links")
	@SecuredAction(value = "", type = ActionType.AUTHENTICATED)
	public void listResourceLinks(HttpServerRequest request) {
		UserUtils.getUserInfos(eb, request, user -> {
			if (user == null) {
				unauthorized(request);
				return;
			}
			final String target = request.params().get("target");
			final String targetId = request.params().get("targetId");
			if (target == null || targetId == null) {
				badRequest(request, "missing.target");
				return;
			}
			final List<String> contexts = new ArrayList<>();
			if (user.getClasses() != null) {
				contexts.addAll(user.getClasses());
			}
			if (user.getGroupsIds() != null) {
				contexts.addAll(user.getGroupsIds());
			}
			ctx.links.listForTarget(target, targetId, user.getUserId(), contexts)
					.onSuccess(links -> renderJson(request, links))
					.onFailure(e -> Http.error(request, e));
		});
	}

	@Delete("/resource-links/:id")
	@SecuredAction(value = "", type = ActionType.AUTHENTICATED)
	public void deleteResourceLink(HttpServerRequest request) {
		UserUtils.getUserInfos(eb, request, user -> {
			if (user == null) {
				unauthorized(request);
				return;
			}
			ctx.links.delete(request.params().get("id"), user.getUserId())
					.onSuccess(rows -> {
						if (rows.isEmpty()) {
							notFound(request);
						} else {
							Http.noContent(request);
						}
					})
					.onFailure(e -> Http.error(request, e));
		});
	}

	// ----------------------------------------------------------------- utilitaires

	private Future<JsonObject> enabledTool(String toolId) {
		return ctx.tools.findTool(toolId).compose(tool -> tool != null && tool.getBoolean("enabled", false)
				? Future.succeededFuture(tool) : Async.<JsonObject>fail(404, "unknown.tool"));
	}

	/** Déploiement de l'outil dans une structure de l'utilisateur (celui du lien s'il est imposé). */
	private Future<JsonObject> deploymentFor(UserInfos user, String toolId, JsonObject link) {
		if (link != null) {
			return ctx.tools.findDeployment(link.getString("deployment_id")).compose(deployment ->
					deployment != null && user.getStructures() != null
							&& user.getStructures().contains(deployment.getString("structure_id"))
							? Future.succeededFuture(deployment)
							: Async.<JsonObject>fail(403, "tool.not.deployed"));
		}
		return ctx.tools.findDeploymentForStructures(toolId, user.getStructures())
				.compose(deployment -> Async.require(deployment, 403, "tool.not.deployed"));
	}

	/** L'utilisateur doit appartenir à la classe ou au groupe utilisé comme contexte. */
	private Future<Void> checkContextAccess(UserInfos user, String contextId) {
		if (contextId == null) {
			return Future.succeededFuture();
		}
		if ((user.getClasses() != null && user.getClasses().contains(contextId))
				|| (user.getGroupsIds() != null && user.getGroupsIds().contains(contextId))) {
			return Future.succeededFuture();
		}
		return ctx.directory.isMember(contextId, user.getUserId())
				.compose(member -> member ? Future.succeededFuture() : Async.<Void>fail(403, "context.forbidden"));
	}

	private String initiationUrl(JsonObject tool, JsonObject hintClaims, String targetLinkUri) {
		final String hint = ctx.tokens.issue(PlatformTokens.TYP_MESSAGE_HINT, hintClaims, LtiContext.now(), HINT_TTL);
		final String base = tool.getString("oidc_initiation_url");
		return base + (base.contains("?") ? "&" : "?")
				+ "iss=" + encode(ctx.issuer)
				+ "&login_hint=" + encode(hintClaims.getString("user"))
				+ "&target_link_uri=" + encode(targetLinkUri)
				+ "&lti_message_hint=" + encode(hint)
				+ "&client_id=" + encode(tool.getString("id"))
				+ "&lti_deployment_id=" + encode(hintClaims.getString("deployment"));
	}

	private static void redirectTo(HttpServerRequest request, String url) {
		request.response().setStatusCode(302).putHeader("Location", url).putHeader("Cache-Control", "no-store").end();
	}

	private static boolean isAdministrator(UserInfos user) {
		return user.getFunctions() != null && (user.getFunctions().containsKey(DefaultFunctions.ADMIN_LOCAL)
				|| user.getFunctions().containsKey(DefaultFunctions.SUPER_ADMIN));
	}

	private static String locale(HttpServerRequest request) {
		final String header = request.headers().get("Accept-Language");
		if (header == null || header.isEmpty()) {
			return null;
		}
		final String first = header.split(",")[0].split(";")[0].trim();
		return first.matches("[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*") ? first : null;
	}

	private static String encode(String value) {
		try {
			return URLEncoder.encode(value == null ? "" : value, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}
}
