package fr.openent.lti.controller;

import fr.openent.lti.LtiContext;
import fr.openent.lti.core.ToolValidator;
import fr.wseduc.rs.Delete;
import fr.wseduc.rs.Get;
import fr.wseduc.rs.Post;
import fr.wseduc.rs.Put;
import fr.wseduc.security.ActionType;
import fr.wseduc.security.SecuredAction;
import fr.wseduc.webutils.http.BaseController;
import fr.wseduc.webutils.request.RequestUtils;
import io.vertx.core.Future;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonObject;
import org.entcore.common.http.filter.AdmlOfStructure;
import org.entcore.common.http.filter.ResourceFilter;
import org.entcore.common.http.filter.SuperAdminFilter;
import org.entcore.common.user.UserUtils;

/**
 * Administration : registre des outils (super administrateur) et activation par structure (ADML).
 */
public class AdminController extends BaseController {

	private final LtiContext ctx;

	public AdminController(LtiContext ctx) {
		this.ctx = ctx;
	}

	/** Informations à saisir dans l'outil pour le relier à la plateforme. */
	@Get("/admin/platform")
	@ResourceFilter(SuperAdminFilter.class)
	@SecuredAction(value = "", type = ActionType.RESOURCE)
	public void platform(HttpServerRequest request) {
		renderJson(request, platformConfiguration());
	}

	@Get("/admin/tools")
	@ResourceFilter(SuperAdminFilter.class)
	@SecuredAction(value = "", type = ActionType.RESOURCE)
	public void listTools(HttpServerRequest request) {
		ctx.tools.listTools()
				.onSuccess(tools -> renderJson(request, tools))
				.onFailure(e -> Http.error(request, e));
	}

	@Post("/admin/tools")
	@ResourceFilter(SuperAdminFilter.class)
	@SecuredAction(value = "", type = ActionType.RESOURCE)
	public void createTool(HttpServerRequest request) {
		RequestUtils.bodyToJson(request, body -> Async.attempt(() -> ToolValidator.validate(body))
				.compose(ctx.tools::createTool)
				.onSuccess(tool -> renderJson(request, new JsonObject()
						.put("tool", tool)
						.put("platform", platformConfiguration().put("client_id", tool.getString("id"))), 201))
				.onFailure(e -> Http.error(request, e)));
	}

	@Put("/admin/tools/:id")
	@ResourceFilter(SuperAdminFilter.class)
	@SecuredAction(value = "", type = ActionType.RESOURCE)
	public void updateTool(HttpServerRequest request) {
		RequestUtils.bodyToJson(request, body -> Async.attempt(() -> ToolValidator.validate(body))
				.compose(tool -> ctx.tools.updateTool(request.params().get("id"), tool))
				.compose(tool -> Async.require(tool, 404, "unknown.tool"))
				.onSuccess(tool -> renderJson(request, tool))
				.onFailure(e -> Http.error(request, e)));
	}

	@Delete("/admin/tools/:id")
	@ResourceFilter(SuperAdminFilter.class)
	@SecuredAction(value = "", type = ActionType.RESOURCE)
	public void deleteTool(HttpServerRequest request) {
		ctx.tools.deleteTool(request.params().get("id"))
				.onSuccess(rows -> {
					if (rows.isEmpty()) {
						notFound(request);
					} else {
						Http.noContent(request);
					}
				})
				.onFailure(e -> Http.error(request, e));
	}

	@Get("/admin/structures/:structureId/deployments")
	@ResourceFilter(AdmlOfStructure.class)
	@SecuredAction(value = "", type = ActionType.RESOURCE)
	public void listDeployments(HttpServerRequest request) {
		ctx.tools.listDeployments(request.params().get("structureId"))
				.onSuccess(rows -> renderJson(request, rows))
				.onFailure(e -> Http.error(request, e));
	}

	@Post("/admin/structures/:structureId/deployments")
	@ResourceFilter(AdmlOfStructure.class)
	@SecuredAction(value = "", type = ActionType.RESOURCE)
	public void createDeployment(HttpServerRequest request) {
		RequestUtils.bodyToJson(request, body -> UserUtils.getUserInfos(eb, request, user -> {
			if (user == null) {
				unauthorized(request);
				return;
			}
			final String toolId = body.getString("toolId");
			ctx.tools.findTool(toolId == null ? "" : toolId)
					.compose(tool -> Async.require(tool, 404, "unknown.tool"))
					.compose(tool -> ctx.tools.createDeployment(toolId, request.params().get("structureId"),
							user.getUserId()))
					.onSuccess(deployment -> renderJson(request, deployment, 201))
					.onFailure(e -> Http.error(request, e));
		}));
	}

	@Delete("/admin/structures/:structureId/deployments/:deploymentId")
	@ResourceFilter(AdmlOfStructure.class)
	@SecuredAction(value = "", type = ActionType.RESOURCE)
	public void deleteDeployment(HttpServerRequest request) {
		ctx.tools.deleteDeployment(request.params().get("structureId"), request.params().get("deploymentId"))
				.compose(rows -> rows.isEmpty() ? Async.<Void>fail(404, "unknown.deployment") : Future.<Void>succeededFuture())
				.onSuccess(v -> Http.noContent(request))
				.onFailure(e -> Http.error(request, e));
	}

	private JsonObject platformConfiguration() {
		return new JsonObject()
				.put("issuer", ctx.issuer)
				.put("authorization_endpoint", ctx.baseUrl + "/auth")
				.put("token_endpoint", ctx.tokenEndpoint())
				.put("jwks_uri", ctx.baseUrl + "/.well-known/jwks.json")
				.put("deep_link_return_url", ctx.baseUrl + "/deeplink/return")
				.put("openid_configuration", ctx.baseUrl + "/.well-known/openid-configuration");
	}
}
