package fr.openent.lti;

import fr.openent.lti.controller.AdminController;
import fr.openent.lti.controller.PlatformController;
import fr.openent.lti.controller.ServiceController;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import org.entcore.common.http.BaseServer;

/**
 * Module LTI 1.3 / LTI Advantage : Open ENT en tant que Platform.
 * Lancement OIDC, Deep Linking 2.0, Assignment and Grade Services 2.0, Names and Role Provisioning Services 2.0.
 */
public class Lti extends BaseServer {

	@Override
	public void start(final Promise<Void> startPromise) throws Exception {
		final Promise<Void> promise = Promise.promise();
		super.start(promise);
		promise.future()
				.compose(v -> initLti())
				.onComplete(startPromise);
	}

	private Future<Void> initLti() {
		final LtiContext context = new LtiContext(vertx, vertx.eventBus(), config);
		return addController(new PlatformController(context))
				.compose(v -> addController(new ServiceController(context)))
				.compose(v -> addController(new AdminController(context)))
				.mapEmpty();
	}
}
