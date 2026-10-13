package fr.openent.lti.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Correspondance profil ENT → rôles LIS v2 (LTI 1.3).
 * Profils ENT : Student, Teacher, Personnel, Relative, Guest.
 */
public final class LtiRoles {

	private static final String MEMBERSHIP = "http://purl.imsglobal.org/vocab/lis/v2/membership#";
	private static final String INSTITUTION = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#";

	public static final String LEARNER = MEMBERSHIP + "Learner";
	public static final String INSTRUCTOR = MEMBERSHIP + "Instructor";
	public static final String MENTOR = MEMBERSHIP + "Mentor";
	public static final String MEMBER = MEMBERSHIP + "Member";
	public static final String ADMINISTRATOR = MEMBERSHIP + "Administrator";

	private LtiRoles() {
	}

	/** Rôle dans le contexte (classe / groupe), utilisé au lancement et par NRPS. */
	public static String contextRole(String profile) {
		if (profile == null) {
			return MEMBER;
		}
		switch (profile) {
			case "Student":
				return LEARNER;
			case "Teacher":
				return INSTRUCTOR;
			case "Personnel":
			case "Relative":
				return MENTOR;
			default:
				return MEMBER;
		}
	}

	public static String institutionRole(String profile) {
		if (profile == null) {
			return INSTITUTION + "Other";
		}
		switch (profile) {
			case "Student":
				return INSTITUTION + "Student";
			case "Teacher":
				return INSTITUTION + "Faculty";
			case "Personnel":
				return INSTITUTION + "Staff";
			case "Guest":
				return INSTITUTION + "Guest";
			default:
				return INSTITUTION + "Other";
		}
	}

	/** Rôles transmis au lancement. Un administrateur (ADML / super admin) reçoit aussi le rôle Administrator. */
	public static List<String> launchRoles(String profile, boolean administrator) {
		final List<String> roles = new ArrayList<>();
		roles.add(contextRole(profile));
		roles.add(institutionRole(profile));
		if (administrator) {
			roles.add(ADMINISTRATOR);
			roles.add(INSTITUTION + "Administrator");
		}
		return roles;
	}

	/** Filtre NRPS « role » : URI complète ou nom court d'un rôle de contexte (ex. Learner). */
	public static boolean matches(String role, String filter) {
		if (filter == null || filter.isEmpty()) {
			return true;
		}
		return role.equals(filter) || role.equals(MEMBERSHIP + filter);
	}

	public static boolean isInstructor(String profile) {
		return INSTRUCTOR.equals(contextRole(profile));
	}
}
