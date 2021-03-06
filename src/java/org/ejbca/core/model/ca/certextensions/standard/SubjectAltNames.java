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

package org.ejbca.core.model.ca.certextensions.standard;

import java.security.PublicKey;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionException;
import org.ejbca.core.model.ca.certextensions.CertificateExtentionConfigurationException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * @author: Tomas Gustavsson
 * @version $Id: SubjectAltNames.java 11882 2011-05-04 08:49:33Z anatom $
 */
public class SubjectAltNames extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(SubjectAltNames.class);

	@Override
	public void init(final CertificateProfile certProf) {
		super.setOID(X509Extensions.SubjectAlternativeName.getId());
		super.setCriticalFlag(certProf.getSubjectAlternativeNameCritical());
	}
	
	@Override
	public DEREncodable getValue(final UserDataVO subject, final CA ca, final CertificateProfile certProfile, final PublicKey userPublicKey, final PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		GeneralNames ret = null;
        String altName = subject.getSubjectAltName(); 
        if(certProfile.getUseSubjectAltNameSubSet()){
        	altName = certProfile.createSubjectAltNameSubSet(altName);
        }
        if ( (altName != null) && (altName.length() > 0) ) {
        	ret = CertTools.getGeneralNamesFromAltName(altName);
        }
		if (ret == null) {
			log.debug("No altnames trying to make SubjectAltName extension: "+altName);
		}
		return ret;
	}	
}
