/**
 * 
 */
package cz.foxon.auth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;

import com.thingworx.logging.LogUtilities;
import com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinition;
import com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinitions;
import com.thingworx.metadata.annotations.ThingworxDataShapeDefinition;
import com.thingworx.metadata.annotations.ThingworxFieldDefinition;
import com.thingworx.security.authentication.AuthenticationUtilities;
import com.thingworx.security.authentication.AuthenticatorException;
import com.thingworx.security.authentication.CustomAuthenticator;

/**
 * Simple authentication for ThingWorx platform that authenticates predefined
 * user.
 * 
 * ThingWorx - Custom Authenticators Overview:
 * https://support.ptc.com/appserver/cs/view/solution.jsp?n=CS244163&lang=en_US
 * Where To Find ThingWorx Documentation (Developer Guide):
 * https://support.ptc.com/appserver/cs/view/solution.jsp?n=CS232833&art_lang=en&posno=1&q=developer&ProductFamily=ThingWorx%7CNRN%7CAxeda&source=search
 * Testing extensions and SDKs outside of ThingWorx within an IDE:
 * https://support.ptc.com/appserver/cs/view/solution.jsp?n=CS215376&art_lang=en&posno=8&q=debug&ProductFamily=ThingWorx%7CNRN%7CAxeda&source=search
 * Using the Eclipse IDE to debug an Extension running in ThingWorx:
 * https://support.ptc.com/appserver/cs/view/solution.jsp?n=CS219756&art_lang=en&posno=1&q=debug&ProductFamily=ThingWorx%7CNRN%7CAxeda&source=search
 *
 * @since 2016-10-13
 * @author Jan Gabriel <jan.gabriel@foxon.cz>
 */

@ThingworxConfigurationTableDefinitions(tables = {
		@ThingworxConfigurationTableDefinition(name = "Settings", description = "Settings for username.", isMultiRow = false, ordinal = 0, dataShape = @ThingworxDataShapeDefinition(fields = {
				@ThingworxFieldDefinition(name = "Username", description = "Please provide username that should be used for auto login feature.", baseType = "STRING", ordinal = 0, aspects = {
						"isRequired:true", "defaultValue:Administrator", "friendlyName:Username" }) })) })

public class AutoAuth extends CustomAuthenticator {

	private static final long serialVersionUID = 814512709216218474L;
	protected static Logger _logger = LogUtilities.getInstance().getApplicationLogger(AutoAuth.class);

	public AutoAuth() {
		/*
		 * Constructor
		 * 
		 * Called by JVM Upon importing extension into ThingWorx, a copy of this
		 * method is sent to the authentication manager so it knows there is
		 * another authenticator to challenge. When the authentication manager
		 * determines by priority that this is the right authenticator, it
		 * instantiates a new instance. Any static data for each new
		 * authenticator instance should be thread safe (final) to avoid causing
		 * deadlocks. Best to avoid putting very much logic here, even calls to
		 * get configuration or instance data (use authenticate method instead).
		 */
	}

	@Override
	public void authenticate(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
			throws AuthenticatorException {
		/*
		 * Authenticate
		 * 
		 * This method needs to throw an Exception or else the authentication
		 * manager will never know there was an error and will always
		 * authenticate the user’s credentials. Sets setCredentials() or throws
		 * AuthenticatorException.
		 */
		try {
			String login = (String)getConfigurationSetting("Settings", "Username");
			AuthenticationUtilities.validateEnabledThingworxUser(login);
			this.setCredentials(login);
		} catch (Exception e) {
			this.setRequiresChallenge(false);
			throw new AuthenticatorException("Provided username is not valid, " + AutoAuth.class.getSimpleName() + " failed to auto login!");
		}
	}

	@Override
	public void issueAuthenticationChallenge(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
			throws AuthenticatorException {
		/*
		 * IssueAuthenticationChallenge
		 * 
		 * This may not be used at all, or it may be used for alerting or
		 * logging. Handles logic which follows authentication fail (e.g.
		 * logging an error: _logger.error). In order to invoke this method,
		 * ensure setRequiresChallenge(true) is in authenticate method before
		 * throwing the exception. ThingworxBasicAuthenticator grabs the
		 * responses and sets some header in this method, then calling the
		 * pop-up box which requests users attempt login again.
		 * ThingworxFormAuthenticator redirects users to plain form login
		 * prompts with return statuses displayed.
		 */
		throw new AuthenticatorException("Provided username is not valid, " + AutoAuth.class.getSimpleName() + " failed to auto login!");
	}

	@Override
	public boolean matchesAuthRequest(HttpServletRequest httpRequest) throws AuthenticatorException {
		/*
		 * MatchesAuthRequest
		 * 
		 * This method determines if this authenticator is valid for the
		 * authentication request type and return true if so.
		 */
		return true;
	}

}
