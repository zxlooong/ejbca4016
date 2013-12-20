/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.approval;

import javax.xml.ws.WebFault;

/**
 * Exception throws after an administrator have approved a request and the
 * request have been executed and something went wrong that the approval
 * administrator should be notified of.
 * 
 * @author Philip Vendil
 * @version $Id: ApprovalRequestExecutionException.java 11201 2011-01-15 10:23:15Z anatom $
 */
@WebFault
public class ApprovalRequestExecutionException extends Exception {


	public ApprovalRequestExecutionException(String message, Throwable cause) {
		super(message, cause);
	}

	public ApprovalRequestExecutionException(String message) {
		super(message);
	}

}
