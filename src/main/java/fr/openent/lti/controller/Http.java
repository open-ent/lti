package fr.openent.lti.controller;

import fr.openent.lti.core.Html;
import fr.openent.lti.core.LtiException;
import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

/** Utilitaires HTTP pour les routes appelées par les outils (hors session ENT). */
final class Http {

	private static final Logger log = LoggerFactory.getLogger(Http.class);
	private static final int MAX_BODY = 1024 * 1024;

	private Http() {
	}

	static Future<MultiMap> form(HttpServerRequest request) {
		final Promise<MultiMap> promise = Promise.promise();
		request.setExpectMultipart(true);
		request.exceptionHandler(promise::tryFail);
		request.endHandler(v -> promise.tryComplete(request.formAttributes()));
		resume(request);
		return promise.future();
	}

	static Future<JsonObject> json(HttpServerRequest request) {
		final Promise<JsonObject> promise = Promise.promise();
		request.exceptionHandler(promise::tryFail);
		request.bodyHandler(buffer -> {
			if (buffer.length() > MAX_BODY) {
				promise.tryFail(new LtiException(413, "body.too.large"));
				return;
			}
			try {
				promise.tryComplete(new JsonObject(buffer.toString("UTF-8")));
			} catch (RuntimeException e) {
				promise.tryFail(new LtiException("invalid.json"));
			}
		});
		resume(request);
		return promise.future();
	}

	/** Paramètre lu dans le formulaire POST, sinon dans la query string. */
	static String param(HttpServerRequest request, MultiMap form, String name) {
		final String value = form != null ? form.get(name) : null;
		return value != null ? value : request.params().get(name);
	}

	static void json(HttpServerRequest request, int status, String contentType, Object body) {
		final String payload = body instanceof JsonArray ? ((JsonArray) body).encode() : ((JsonObject) body).encode();
		request.response()
				.setStatusCode(status)
				.putHeader("Content-Type", contentType + "; charset=utf-8")
				.putHeader("Cache-Control", "no-store")
				.end(payload);
	}

	static void html(HttpServerRequest request, int status, String html) {
		request.response()
				.setStatusCode(status)
				.putHeader("Content-Type", "text/html; charset=utf-8")
				.putHeader("Cache-Control", "no-store")
				.putHeader("Referrer-Policy", "no-referrer")
				.end(html);
	}

	static void noContent(HttpServerRequest request) {
		request.response().setStatusCode(204).end();
	}

	/** Erreur au format JSON (services AGS/NRPS, jeton). */
	static void error(HttpServerRequest request, Throwable error) {
		if (error instanceof LtiException) {
			final LtiException e = (LtiException) error;
			json(request, e.getStatus(), "application/json", new JsonObject().put("error", e.getMessage()));
		} else {
			log.error("[LTI] Unexpected error", error);
			json(request, 500, "application/json", new JsonObject().put("error", "server_error"));
		}
	}

	/** Erreur sous forme de page HTML (parcours navigateur). */
	static void htmlError(HttpServerRequest request, Throwable error) {
		if (error instanceof LtiException) {
			html(request, ((LtiException) error).getStatus(), Html.message("LTI", error.getMessage()));
		} else {
			log.error("[LTI] Unexpected error", error);
			html(request, 500, Html.message("LTI", "server_error"));
		}
	}

	static int intParam(HttpServerRequest request, String name, int defaultValue, int max) {
		try {
			final String value = request.params().get(name);
			final int parsed = value == null ? defaultValue : Integer.parseInt(value);
			return Math.max(0, Math.min(parsed, max));
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	private static void resume(HttpServerRequest request) {
		try {
			request.resume();
		} catch (Exception ignored) {
			// déjà consommé
		}
	}
}
