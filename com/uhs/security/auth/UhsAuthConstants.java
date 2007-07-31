/*
 * Created on Aug 14, 2006
 *
 * (C) Copyright 2006 IBM Corp. All Rights Reserved.
 */
package com.uhs.security.auth;

/**
 * @author mshade
 *
 * This interface contains security/authentication related constants.
 */
public interface UhsAuthConstants {
	static final String COPYRIGHT = "(C) Copyright 2006 IBM Corp. All Rights Reserved.";
	
	public static String DEBUG_KEY    = "debug";
	public static String CALLBACK_KEY = "UHS_CALLBACK_ID";
	
	public static int USER_ID_CALLBACK_IDX  = 0;
	public static int USER_PWD_CALLBACK_IDX = 1;
	public static int NUM_CALLBACKS         = 2;	

}  // END interface UhsAuthConstants
