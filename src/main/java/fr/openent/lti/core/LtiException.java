package fr.openent.lti.core;

/**
 * Erreur fonctionnelle LTI : message destiné à l'appelant (outil ou navigateur) et code HTTP associé.
 */
public class LtiException extends Exception {

	private final int status;

	public LtiException(String message) {
		this(400, message);
	}

	public LtiException(int status, String message) {
		super(message);
		this.status = status;
	}

	public int getStatus() {
		return status;
	}
}
