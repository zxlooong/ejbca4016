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

package org.ejbca.core.ejb.ca.publisher;

import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.Authorizer;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.CertTools;
import org.ejbca.util.ProfileID;

/**
 * Handles management of Publishers.
 * 
 * @version $Id: PublisherSessionBean.java 17223 2013-06-26 19:00:23Z netmackan $
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "PublisherSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherSessionBean implements PublisherSessionLocal, PublisherSessionRemote {

    private static final Logger log = Logger.getLogger(PublisherSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private LogSessionLocal logSession;

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void flushPublisherCache() {
        PublisherCache.INSTANCE.flush();
        if (log.isDebugEnabled()) {
            log.debug("Flushed Publisher cache.");
        }
    }

    @Override
    public boolean storeCertificate(Admin admin, Collection<Integer> publisherids, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) {
        return storeCertificate(admin, LogConstants.EVENT_INFO_STORECERTIFICATE, LogConstants.EVENT_ERROR_STORECERTIFICATE, publisherids, incert, username,
                password, userDN, cafp, status, type, revocationDate, revocationReason, tag, certificateProfileId, lastUpdate, extendedinformation);
    }

    @Override
    public void revokeCertificate(Admin admin, Collection<Integer> publisherids, Certificate cert, String username, String userDN, String cafp, int type, int reason,
            long revocationDate, String tag, int certificateProfileId, long lastUpdate) {
        storeCertificate(admin, LogConstants.EVENT_INFO_REVOKEDCERT, LogConstants.EVENT_ERROR_REVOKEDCERT, publisherids, cert, username, null, userDN, cafp,
                SecConst.CERT_REVOKED, type, revocationDate, reason, tag, certificateProfileId, lastUpdate, null);
    }

    /**
     * The same basic method is be used for both store and revoke
     * @return true if publishing was successful for all publishers (or no publishers were given as publisherids), false if not or if was queued for any of the publishers
     */
    private boolean storeCertificate(Admin admin, int logInfoEvent, int logErrorEvent, Collection<Integer> publisherids, Certificate cert, String username,
            String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId,
            long lastUpdate, ExtendedInformation extendedinformation) {
    	if (publisherids == null) {
    		return true;
    	}
        boolean returnval = true;
        for (Integer id : publisherids) {
            int publishStatus = PublisherConst.STATUS_PENDING;
            BasePublisher publ = getPublisher(admin, id);
            if (publ != null) {
                // If the publisher will not publish the certificate, break out directly and do not call the publisher or queue the certificate
            	if (publ.willPublishCertificate(status, revocationReason)) {
            		String fingerprint = CertTools.getFingerprintAsString(cert);
            		final String name = getPublisherName(admin, id);
            		// If it should be published directly
            		if (!publ.getOnlyUseQueue()) {
            			try {
            				try {
            					if (publisherQueueSession.storeCertificateNonTransactional(publ, admin, cert, username, password, userDN, cafp, status, type, revocationDate, revocationReason,
            							tag, certificateProfileId, lastUpdate, extendedinformation)) {
            						publishStatus = PublisherConst.STATUS_SUCCESS;
            					}
            				} catch (EJBException e) {
            					final Throwable t = e.getCause();
            					if (t instanceof PublisherException) {
            						throw (PublisherException)t;
            					} else {
            						throw e;
            					}
            				}
            				final String msg = intres.getLocalizedMessage("publisher.store", CertTools.getSubjectDN(cert), name);
            				logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logInfoEvent, msg);
            			} catch (PublisherException pe) {
            				final String msg = intres.getLocalizedMessage("publisher.errorstore", name, fingerprint);
            				logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logErrorEvent, msg, pe);
            			}
            		}
            		if (publishStatus != PublisherConst.STATUS_SUCCESS) {
            			returnval = false;
            		}
            		if (log.isDebugEnabled()) {
            			log.debug("KeepPublishedInQueue: " + publ.getKeepPublishedInQueue());
            			log.debug("UseQueueForCertificates: " + publ.getUseQueueForCertificates());
            		}
            		if ((publishStatus != PublisherConst.STATUS_SUCCESS || publ.getKeepPublishedInQueue())
            				&& publ.getUseQueueForCertificates()) {
            			// Write to the publisher queue either for audit reasons or to be able try again
            			PublisherQueueVolatileData pqvd = new PublisherQueueVolatileData();
            			pqvd.setUsername(username);
            			pqvd.setPassword(password);
            			pqvd.setExtendedInformation(extendedinformation);
            			pqvd.setUserDN(userDN);
            			String fp = CertTools.getFingerprintAsString(cert);
            			try {
            				publisherQueueSession.addQueueData(id.intValue(), PublisherConst.PUBLISH_TYPE_CERT, fp, pqvd, publishStatus);
            				final String msg = intres.getLocalizedMessage("publisher.storequeue", name, fp, status);
            				logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logInfoEvent, msg);
            			} catch (CreateException e) {
            				final String msg = intres.getLocalizedMessage("publisher.errorstorequeue", name, fp, status);
            				logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logErrorEvent, msg, e);
            			}                		
            		}
            	} else {
            		if (log.isDebugEnabled()) {
            			log.debug("Not storing or queuing certificate for Publisher with id "+id+" because publisher will not publish it.");
            		}
            	}
            } else {
                String msg = intres.getLocalizedMessage("publisher.nopublisher", id);
                logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), null, cert, logErrorEvent, msg);
                returnval = false;
            }
        }
        return returnval;
    }
    
    @Override
    public boolean storeCRL(Admin admin, Collection<Integer> publisherids, byte[] incrl, String cafp, int number, String userDN) {
    	if (log.isTraceEnabled()) {
    		log.trace(">storeCRL");
    	}
        Iterator<Integer> iter = publisherids.iterator();
        boolean returnval = true;
        while (iter.hasNext()) {
            int publishStatus = PublisherConst.STATUS_PENDING;
            Integer id = iter.next();
            final BasePublisher publ = getPublisher(admin, id);
            if (publ != null) {
                final String name = getPublisherName(admin, id);
                // If it should be published directly
                if (!publ.getOnlyUseQueue()) {
                    try {
                        try {
                            if (publisherQueueSession.storeCRLNonTransactional(publ, admin, incrl, cafp, number, userDN)) {
                                publishStatus = PublisherConst.STATUS_SUCCESS;
                            }
                            String msg = intres.getLocalizedMessage("publisher.store", "CRL", name);
                            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_STORECRL, msg);
                        } catch (EJBException e) {
                            final Throwable t = e.getCause();
                            if (t instanceof PublisherException) {
                                throw (PublisherException) t;
                            } else {
                                throw e;
                            }
                        }
                    } catch (PublisherException pe) {
                        String msg = intres.getLocalizedMessage("publisher.errorstore", name, "CRL");
                        logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL,
                                msg, pe);
                    }
                }
                if (publishStatus != PublisherConst.STATUS_SUCCESS) {
                    returnval = false;
                }
                if (log.isDebugEnabled()) {
                    log.debug("KeepPublishedInQueue: " + publ.getKeepPublishedInQueue());
                    log.debug("UseQueueForCRLs: " + publ.getUseQueueForCRLs());
                }
                if ((publishStatus != PublisherConst.STATUS_SUCCESS || publ.getKeepPublishedInQueue())
                        && publ.getUseQueueForCRLs()) {
                    // Write to the publisher queue either for audit reasons or
                    // to be able try again
                    final PublisherQueueVolatileData pqvd = new PublisherQueueVolatileData();
                    pqvd.setUserDN(userDN);
                    String fp = CertTools.getFingerprintAsString(incrl);
                    try {
                        publisherQueueSession.addQueueData(id.intValue(), PublisherConst.PUBLISH_TYPE_CRL, fp, pqvd, PublisherConst.STATUS_PENDING);
                        String msg = intres.getLocalizedMessage("publisher.storequeue", name, fp, "CRL");
                        logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_STORECRL, msg);
                    } catch (CreateException e) {
                        String msg = intres.getLocalizedMessage("publisher.errorstorequeue", name, fp, "CRL");
                        logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL,
                                msg, e);
                    }
                }
            } else {
                String msg = intres.getLocalizedMessage("publisher.nopublisher", id);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL, msg);
                returnval = false;
            }
        }
        if (log.isTraceEnabled()) {
        	log.trace("<storeCRL");
        }
        return returnval;
    }

    @Override
    public void testConnection(Admin admin, int publisherid) throws PublisherConnectionException {
        if (log.isTraceEnabled()) {
            log.trace(">testConnection(id: " + publisherid + ")");
        }
        PublisherData pdl = PublisherData.findById(entityManager, Integer.valueOf(publisherid));
        if (pdl != null) {
            String name = pdl.getName();
            try {
                getPublisher(pdl).testConnection(admin);
                String msg = intres.getLocalizedMessage("publisher.testedpublisher", name);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
            } catch (PublisherConnectionException pe) {
                String msg = intres.getLocalizedMessage("publisher.errortestpublisher", name);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg,
                        pe);
                throw new PublisherConnectionException(pe.getMessage());
            }
        } else {
            String msg = intres.getLocalizedMessage("publisher.nopublisher", Integer.valueOf(publisherid));
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);

        }
        if (log.isTraceEnabled()) {
            log.trace("<testConnection(id: " + publisherid + ")");
        }
    }

    @Override
    public void addPublisher(Admin admin, String name, BasePublisher publisher) throws PublisherExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addPublisher(name: " + name + ")");
        }
        addPublisher(admin, findFreePublisherId(), name, publisher);
        log.trace("<addPublisher()");
    }

    @Override
    public void addPublisher(Admin admin, int id, String name, BasePublisher publisher) throws PublisherExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addPublisher(name: " + name + ", id: " + id + ")");
        }
        boolean success = false;
        if (PublisherData.findByName(entityManager, name) == null) {
            if (PublisherData.findById(entityManager, Integer.valueOf(id)) == null) {
                try {
                	entityManager.persist(new PublisherData(Integer.valueOf(id), name, publisher));
                    success = true;
                } catch (Exception e) {
                    String msg = intres.getLocalizedMessage("publisher.erroraddpublisher", name);
                    log.error(msg, e);
                }
            }
        }
        if (success) {
            String msg = intres.getLocalizedMessage("publisher.addedpublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("publisher.erroraddpublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
            throw new PublisherExistsException();
        }
        log.trace("<addPublisher()");
    }

    @Override
    public void changePublisher(Admin admin, String name, BasePublisher publisher) {
        if (log.isTraceEnabled()) {
            log.trace(">changePublisher(name: " + name + ")");
        }
        PublisherData htp = PublisherData.findByName(entityManager, name);
        if (htp != null) {
            htp.setPublisher(publisher);
            // Since loading a Publisher is quite complex, we simple purge the cache here
            PublisherCache.INSTANCE.removeEntry(htp.getId());            
            final String msg = intres.getLocalizedMessage("publisher.changedpublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("publisher.errorchangepublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
        }
        log.trace("<changePublisher()");
    }

    @Override
    public void clonePublisher(Admin admin, String oldname, String newname) {
        if (log.isTraceEnabled()) {
            log.trace(">clonePublisher(name: " + oldname + ")");
        }
        BasePublisher publisherdata = null;
        try {
        	PublisherData htp = PublisherData.findByName(entityManager, oldname);
        	if (htp == null) {
        		throw new Exception("Could not find publisher " + oldname);
        	}
            publisherdata = (BasePublisher) getPublisher(htp).clone();
            try {
                addPublisher(admin, newname, publisherdata);
                String msg = intres.getLocalizedMessage("publisher.clonedpublisher", newname, oldname);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
            } catch (PublisherExistsException f) {
                String msg = intres.getLocalizedMessage("publisher.errorclonepublisher", newname, oldname);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
                throw f;
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("publisher.errorclonepublisher", newname, oldname);
            log.error(msg, e);
            throw new EJBException(e);	// TODO: This might be a bit too much...
        }
        log.trace("<clonePublisher()");
    }

    @Override
    public void removePublisher(Admin admin, String name) {
        if (log.isTraceEnabled()) {
            log.trace(">removePublisher(name: " + name + ")");
        }
        try {
            PublisherData htp = PublisherData.findByName(entityManager, name);
            if (htp == null) {
            	if (log.isDebugEnabled()) {
            		log.debug("Trying to remove a publisher that does not exist: "+name);                		
            	}
            } else {
            	entityManager.remove(htp);
                // Purge the cache here
                PublisherCache.INSTANCE.removeEntry(htp.getId());            
                String msg = intres.getLocalizedMessage("publisher.removedpublisher", name);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("publisher.errorremovepublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg, e);
        }
        log.trace("<removePublisher()");
    }

    @Override
    public void renamePublisher(Admin admin, String oldname, String newname) throws PublisherExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">renamePublisher(from " + oldname + " to " + newname + ")");
        }
        boolean success = false;
        if (PublisherData.findByName(entityManager, newname) == null) {
        	PublisherData htp = PublisherData.findByName(entityManager, oldname);
        	if (htp != null) {
                htp.setName(newname);
                success = true;
                // Since loading a Publisher is quite complex, we simple purge the cache here
                PublisherCache.INSTANCE.removeEntry(htp.getId());            
            }
        }
        if (success) {
            String msg = intres.getLocalizedMessage("publisher.renamedpublisher", oldname, newname);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("publisher.errorrenamepublisher", oldname, newname);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
            throw new PublisherExistsException();
        }
        log.trace("<renamePublisher()");
    }

    @Override
    public Collection<Integer> getAllPublisherIds(Admin admin) throws AuthorizationDeniedException {
        HashSet<Integer> returnval = new HashSet<Integer>();
        if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
            Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR, null);
        }
        Iterator<PublisherData> i = PublisherData.findAll(entityManager).iterator();
        while (i.hasNext()) {
        	returnval.add(i.next().getId());
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public HashMap<Integer,String> getPublisherIdToNameMap(Admin admin) {
        HashMap<Integer,String> returnval = new HashMap<Integer,String>();
        Iterator<PublisherData> i = PublisherData.findAll(entityManager).iterator();
        while (i.hasNext()) {
        	PublisherData next = i.next();
        	returnval.put(next.getId(), next.getName());
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public BasePublisher getPublisher(Admin admin, String name) {
        return getPublisherInternal(-1, name, true);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public BasePublisher getPublisher(Admin admin, int id) {
        return getPublisherInternal(id, null, true);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public int getPublisherUpdateCount(Admin admin, int publisherid) {
        int returnval = 0;
        PublisherData pd = PublisherData.findById(entityManager, Integer.valueOf(publisherid));
        if (pd != null) {
        	returnval = pd.getUpdateCounter();
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public int getPublisherId(Admin admin, String name) {
        getPublisher(admin, name);
        final Integer val = PublisherCache.INSTANCE.getNameToIdMap().get(name);
        return (val != null) ? val : 0;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getPublisherName(Admin admin, int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getPublisherName(id: " + id + ")");
        }
        // Get publisher to ensure it is in the cache
        getPublisher(admin, id);
        final String name = PublisherCache.INSTANCE.getName(id);
        if (log.isTraceEnabled()) {
        	log.trace("<getPublisherName()");
        }
        return name;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String testAllConnections() {
        log.trace(">testAllPublishers");
        String returnval = "";
        Admin admin = Admin.getInternalAdmin();
        Iterator<PublisherData> i = PublisherData.findAll(entityManager).iterator();
        while (i.hasNext()) {
        	PublisherData pdl = i.next();
        	String name = pdl.getName();
        	try {
        		getPublisher(pdl).testConnection(admin);
        	} catch (PublisherConnectionException pe) {
        		String msg = intres.getLocalizedMessage("publisher.errortestpublisher", name);
        		logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA,
        				msg, pe);
        		returnval += "\n" + msg;
        	}
        }
        log.trace("<testAllPublishers");
        return returnval;
    }

    @Override
    public void internalChangeCertificateProfileNoFlushCache(Admin admin, String name, BasePublisher publisher) throws AuthorizationDeniedException {
        // Check that administrator has superadminstrator rights.
        if(!authorizationSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", "internalChangeCertificateProfileNoFlushCache");
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg);
            throw new AuthorizationDeniedException(msg);
        }
        PublisherData htp = PublisherData.findByName(entityManager, name);
        if (htp != null) {
            htp.setPublisher(publisher);
        }
    }

    private int findFreePublisherId() {
		final ProfileID.DB db = new ProfileID.DB() {
			@Override
			public boolean isFree(int i) {
				return PublisherData.findById(PublisherSessionBean.this.entityManager, i)==null;
			}
		};
		return ProfileID.getNotUsedID(db);
    }

    /**
     * Internal method for getting Publisher, to avoid code duplication. Tries to find the Publisher even if the id is wrong due to CA certificate DN not being
     * the same as CA DN. Uses PublisherCache directly if configured to do so.
     * 
     * Note! No authorization checks performed in this internal method
     * 
     * @param id
     *            numerical id of Publisher that we search for, or -1 if a name is to be used instead
     * @param name
     *            human readable name of Publisher, used instead of id if id == -1, can be null if id != -1
     * @param fromCache if we should use the cache or return a new, decoupled, instance from the database, to be used when you need
     *             a completely distinct object, for edit, and not a shared cached instance.
     * @return BasePublisher value object or null if it does not exist
     */
    private BasePublisher getPublisherInternal(int id, final String name, boolean fromCache) {
        if (log.isTraceEnabled()) {
            log.trace(">getPublisherInternal: " + id + ", " + name);
        }
        Integer idValue = Integer.valueOf(id);
        if (id == -1) {
            idValue = PublisherCache.INSTANCE.getNameToIdMap().get(name);
        }
        BasePublisher returnval = null;
        // If we should read from cache, and we have an id to use in the cache, and the cache does not need to be updated
        if (fromCache && idValue!=null && !PublisherCache.INSTANCE.shouldCheckForUpdates(idValue)) {
            // Get from cache (or null)
            returnval = PublisherCache.INSTANCE.getEntry(idValue);
        }

        // if we selected to not read from cache, or if the cache did not contain this entry
        if (returnval == null) {
        	if (log.isDebugEnabled()) {
        	    log.debug("Publisher with ID " + idValue + " and/or name '"+name+"' will be checked for updates.");
        	}
            // We need to read from database because we specified to not get from cache or we don't have anything in the cache
            final PublisherData pd;
            if (name != null) {
                pd = PublisherData.findByName(entityManager, name);
            } else {
                pd = PublisherData.findById(entityManager, idValue);
            }
            if (pd != null) {
                returnval = getPublisher(pd);
                final int digest = pd.getProtectString(0).hashCode();
                // The cache compares the database data with what is in the cache
                // If database is different from cache, replace it in the cache
                PublisherCache.INSTANCE.updateWith(pd.getId(), digest, pd.getName(), returnval);
            } else {
                // Ensure that it is removed from cache if it exists
                if (idValue != null) {
                    PublisherCache.INSTANCE.removeEntry(idValue);                    
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getPublisherInternal: " + id + ", " + name+": "+(returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    /** @return the publisher data and updates it if necessary. */
    private BasePublisher getPublisher(PublisherData pData) {
        BasePublisher publisher = pData.getCachedPublisher();
        if (publisher == null) {
            java.beans.XMLDecoder decoder;
            try {
                decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(pData.getData().getBytes("UTF8")));
            } catch (UnsupportedEncodingException e) {
                throw new EJBException(e);
            }
            HashMap h = (HashMap) decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            HashMap data = new Base64GetHashMap(h);

            switch (((Integer) (data.get(BasePublisher.TYPE))).intValue()) {
            case PublisherConst.TYPE_LDAPPUBLISHER:
                publisher = new LdapPublisher();
                break;
            case PublisherConst.TYPE_LDAPSEARCHPUBLISHER:
                publisher = new LdapSearchPublisher();
                break;
            case PublisherConst.TYPE_ADPUBLISHER:
                publisher = new ActiveDirectoryPublisher();
                break;
            case PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER:
                publisher = new CustomPublisherContainer();
                break;
            case PublisherConst.TYPE_VAPUBLISHER:
                publisher = new ValidationAuthorityPublisher();
                break;
            }
            publisher.loadData(data);
        }
        return publisher;
    }
}
