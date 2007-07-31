/*
 * Created on Aug 11, 2006
 *
 * (C) Copyright 2006 IBM Corp. All Rights Reserved.
 */
package com.uhs.security.auth;

import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * @author mshade
 * 
 * This class provides function as a JAAS login module.
 * It's purpose is to retrieve the logged in user's id and password.
 * It will save the user's credentials in the WSSubject.
 * The credentials can then be retrieved at a later time.
 */
public class UhsCustomLoginModule implements LoginModule {
	static final String COPYRIGHT = "(C) Copyright 2006 IBM Corp. All Rights Reserved.";
	
	private final String CLASSNAME = getClass().getName();
		
	private CallbackHandler callbackHandler = null;
	private Map sharedState = null;
	private Map options = null;
	private Subject subject = null;
	private boolean loggedIn = false;
	private boolean debugEnabled = false;  // (WAS) configurable debug enablement

	/**
	 * (non-Javadoc)
	 * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
	 */
	public void initialize(Subject theSubject, CallbackHandler theCallbackHandler, Map theSharedState, Map theOptions) {
		final String methodName = "initialize";
		
		// Initialize any configured options
		// If the debug key is defined with any value, debug is enabled
		debugEnabled = theOptions.get(UhsAuthConstants.DEBUG_KEY) != null;
		
		debug(CLASSNAME, methodName, "ENTRY");
		
		subject = theSubject;
		callbackHandler = theCallbackHandler;
		sharedState = theSharedState;
		options = theOptions;
		
		debug(CLASSNAME, methodName, "Debug enablement: " + debugEnabled);
		debug(CLASSNAME, methodName, "EXIT");
	}
	
	/**
	 * (non-Javadoc)
	 * @see javax.security.auth.spi.LoginModule#login()
	 */
	public boolean login() throws LoginException {
		final String methodName = "login";
		
		debug(CLASSNAME, methodName, "ENTRY");
		
		Callback aCallbackArray[] = new Callback[UhsAuthConstants.NUM_CALLBACKS];
		
		aCallbackArray[UhsAuthConstants.USER_ID_CALLBACK_IDX] = new NameCallback("userName:");
		aCallbackArray[UhsAuthConstants.USER_PWD_CALLBACK_IDX] = new PasswordCallback("userPassword:", false);
		try {
			debug(CLASSNAME, methodName, "BEGIN callback handler...");
			callbackHandler.handle(aCallbackArray);
			debug(CLASSNAME, methodName, "SUCCESS from callback handler");
		} catch(java.io.IOException e) {
			e.printStackTrace();
			throw new LoginException(e.toString());
		} catch(UnsupportedCallbackException e) {
			e.printStackTrace();
			throw new LoginException("Callback handler problem: " + e.getCallback()); 
		}
		
		String aUserName = new String(((NameCallback)aCallbackArray[UhsAuthConstants.USER_ID_CALLBACK_IDX]).getName());
		String aUserPwd = new String(((PasswordCallback)aCallbackArray[UhsAuthConstants.USER_PWD_CALLBACK_IDX]).getPassword());
		
		debug(CLASSNAME, methodName, "From custom JAAS login Module ->");
		debug(CLASSNAME, methodName, "  USER NAME: " + aUserName);
		debug(CLASSNAME, methodName, "  USER PASSWORD: " + aUserPwd);
		debug(CLASSNAME, methodName, "Map size (shared state) : " + sharedState.size());
		
		try {
			sharedState.put(UhsAuthConstants.CALLBACK_KEY, aCallbackArray);
			loggedIn = true;
		} catch (RuntimeException e) {
			debug(CLASSNAME, methodName, "Error adding information to the shared state");
			loggedIn = false;
			e.printStackTrace();
			throw new FailedLoginException("Unable to add information to the shared state");
		}

		debug(CLASSNAME, methodName, "EXIT");
		
		return loggedIn;
	}
	
	/**
	 * (non-Javadoc)
	 * @see javax.security.auth.spi.LoginModule#commit()
	 * 
	 * This method is only invoked by the Application Server run time in case
	 * the whole JAAS login module stack succeeded in authenticating the user. 
	 * If the authentication failed, the abort() method is called which sets
	 * the custom credential to null.
	 */
	public boolean commit() throws LoginException {
		final String methodName = "commit";

		debug(CLASSNAME, methodName, "ENTRY");
		
		// Add the (private) credentials to the credential set for later retrieval.
		Callback[] aCallbackArray = (Callback[])sharedState.get(UhsAuthConstants.CALLBACK_KEY);
		UhsUserCredential aCredential = new UhsUserCredential(aCallbackArray);
		Set aCredentialSet = subject.getPrivateCredentials();
		aCredentialSet.add(aCredential);
		
		debug(CLASSNAME, methodName, "Credential successfully added (committed) to the credential set");
		debug(CLASSNAME, methodName, "EXIT");
		
		return true;
	}
	
	/**
	 * (non-Javadoc)
	 * @see javax.security.auth.spi.LoginModule#abort()
	 * 
	 * This method is called if authentication fails.
	 */
	public boolean abort() throws LoginException {
		final String methodName = "abort";
		
		debug(CLASSNAME, methodName, "ENTRY");
		debug(CLASSNAME, methodName, "Calling logout() to handle abort processing");
		debug(CLASSNAME, methodName, "EXIT");
		
		return logout();
	}

	/**
	 * (non-Javadoc)
	 * @see javax.security.auth.spi.LoginModule#logout()
	 */
	public boolean logout() throws LoginException {
		final String methodName = "logout";
		
		debug(CLASSNAME, methodName, "ENTRY");
		
		boolean bIsSuccess = true;
		
		if (!loggedIn) {
			// Ignore the logout request.
			bIsSuccess = false;
		}
		else {
			try {
				debug(CLASSNAME, methodName, "BEGIN removing callback from shared state...");
				sharedState.remove(UhsAuthConstants.CALLBACK_KEY);
				debug(CLASSNAME, methodName, "SUCCESS removing callback from shared state");
			} catch (UnsupportedOperationException e) {
				String aMsg = "Unable to remove callback from shared state, the operation is not supported!";
				debug(CLASSNAME, methodName, aMsg);
				e.printStackTrace();
				throw new FailedLoginException(aMsg);
			}
		}
		
		cleanup();
		
		debug(CLASSNAME, methodName, "return " + bIsSuccess);		
		debug(CLASSNAME, methodName, "EXIT");
		
		return bIsSuccess;
	}
	
	/**
	 *  Clean up object references.
	 */
	protected void cleanup() {
		final String methodName = "cleanup";
		
		debug(CLASSNAME, methodName, "ENTRY");
		
		this.subject = null;
		this.callbackHandler = null;
		this.sharedState = null;
		this.options = null;
		this.loggedIn = false;
		this.debugEnabled = false;
		
		debug(CLASSNAME, methodName, "EXIT");
	}
	
	/**
	* This will output debug/trace messages.
	* 
	* @param String theClass - the name of the class
	* @param String theMethod - the name of the method
	* @param String theMsg - the message to output
	*/
	public void debug(String theClass, String theMethod, String theMsg) {
		if (debugEnabled)
			System.out.println(theClass + "." + theMethod + ": " + theMsg);
	}
	
}  // END class UhsCustomLoginModule
