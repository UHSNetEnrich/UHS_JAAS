/*
 * Created on Aug 11, 2006
 *
 * (C) Copyright 2006 IBM Corp. All Rights Reserved.
 */
package com.uhs.security.auth;

/**
 * @author mshade
 * 
 * This class contains custom user credential information.
 * It is used by a custom JAAS login module.
 * 
 * @see com.uhs.security.auth.UhsCustomLoginModule
 */
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

public class UhsUserCredential {
	static final String COPYRIGHT = "(C) Copyright 2006 IBM Corp. All Rights Reserved.";
	
	String userName = null;
	String userPwd = null;

	/**
	 * Constructor
	 *
	 * Assigns the user id and password values for the logged in user via callbacks.
	 *  
	 * @param Callback list
	 */
	public UhsUserCredential(Callback[] theCallbackArray) {
		userName = new String(((NameCallback)theCallbackArray[UhsAuthConstants.USER_ID_CALLBACK_IDX]).getName());
		userPwd = new String(((PasswordCallback)theCallbackArray[UhsAuthConstants.USER_PWD_CALLBACK_IDX]).getPassword());
	}

	/**
	 * Get the user name of the user attempting to log in.
	 * 
	 * @return String user name
	 */
	public String getUserName() {
		return userName;
	}

	/**
	 * Get the user password of the user attempting to log in.
	 * 
	 * @return String user password
	 */
	public String getPassword() {
		return userPwd;
	}
	
}  // END class UhsUserCredential
