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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests Publisher session.
 * 
 * @version $Id: PublisherSessionTest.java 16276 2013-02-05 13:57:56Z anatom $
 */
public class PublisherSessionTest {

    private static final Admin internalAdmin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);

    private ConfigurationSessionRemote configSession = InterfaceCache.getConfigurationSession();
    private PublisherSessionRemote publisherSession = InterfaceCache.getPublisherSession();

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testAddChangeRemovePublisher() throws PublisherExistsException, AuthorizationDeniedException {
        ValidationAuthorityPublisher publ = new ValidationAuthorityPublisher();
        publ.setDataSource("foo");
        publ.setDescription("foobar");
        ValidationAuthorityPublisher publ1 = new ValidationAuthorityPublisher();
        publ1.setDataSource("bar");
        publ1.setDescription("barfoo");
        final String name = PublisherSessionTest.class.getSimpleName();
        final String name1 = PublisherSessionTest.class.getSimpleName()+"1";
        try {
            // Test some initial empty checks to see we do not get NPEs
            int noid = publisherSession.getPublisherId(internalAdmin, name);
            assertEquals(0, noid);
            String noname = publisherSession.getPublisherName(internalAdmin, 123);
            assertNull(noname);
            // Add new publisher
            publisherSession.addPublisher(internalAdmin, name, publ);
            publisherSession.addPublisher(internalAdmin, name1, publ1);
            BasePublisher pub = publisherSession.getPublisher(internalAdmin, name);
            assertEquals("Description is not what we set", "foobar", pub.getDescription());
            assertEquals("Publisher is not a ValidationAuthorityPublisher", ValidationAuthorityPublisher.class.getName(), pub.getClass().getName());
            assertEquals("datasource is not what we set", "foo", ((ValidationAuthorityPublisher)pub).getDataSource());
            int id = publisherSession.getPublisherId(internalAdmin, name);
            BasePublisher pub1 = publisherSession.getPublisher(internalAdmin, id);
            assertEquals("Description is not what we set", "foobar", pub1.getDescription());
            assertEquals("Publisher is not a ValidationAuthorityPublisher", ValidationAuthorityPublisher.class.getName(), pub1.getClass().getName());
            assertEquals("datasource is not what we set", "foo", ((ValidationAuthorityPublisher)pub1).getDataSource());
            // Change publisher
            pub.setDescription("newdesc");
            publisherSession.changePublisher(internalAdmin, name, pub);
            pub = publisherSession.getPublisher(internalAdmin, name);
            assertEquals("Description is not what we set", "newdesc", pub.getDescription());
            assertEquals("Publisher is not a ValidationAuthorityPublisher", ValidationAuthorityPublisher.class.getName(), pub.getClass().getName());
            assertEquals("datasource is not what we set", "foo", ((ValidationAuthorityPublisher)pub).getDataSource());
            int id1 = publisherSession.getPublisherId(internalAdmin, name);
            assertEquals("Id should be the same after change, but it is not", id, id1);
            // Remove publishers
            publisherSession.removePublisher(internalAdmin, name);
            publisherSession.removePublisher(internalAdmin, name1);
            assertNull("Should return null when publisher does not exist", publisherSession.getPublisher(internalAdmin, name));
            assertNull("Should return null when publisher does not exist", publisherSession.getPublisher(internalAdmin, name1));
            assertNull("Should return null when publisher does not exist", publisherSession.getPublisher(internalAdmin, id));
        } finally {
            publisherSession.removePublisher(internalAdmin, name);
            publisherSession.removePublisher(internalAdmin, name1);            
        }
    }
    
    /**
     * Test of the cache of publishers. This test depends on the default cache time of 1 second being used.
     * If you changed this config, publisher.cachetime, this test may fail. 
     */
    @Test
    public void testPublisherCache() throws Exception {
        // First make sure we have the right cache time
        final String oldcachetime = configSession.getProperty("publisher.cachetime", null);
        configSession.updateProperty("publisher.cachetime", "1000");
        ValidationAuthorityPublisher publ = new ValidationAuthorityPublisher();
        publ.setDescription("foobar");
        final String name = PublisherSessionTest.class.getSimpleName();
        try {
            // Add a publisher
            publisherSession.addPublisher(internalAdmin, name, publ);
            // Make sure publisher has the right value from the beginning
            BasePublisher pub = publisherSession.getPublisher(internalAdmin, name);
            assertEquals("Description is not what we set", "foobar", pub.getDescription());
            // Change publisher
            pub.setDescription("bar");
            publisherSession.changePublisher(internalAdmin, name, pub);
            // Read publisher again, cache should have been updated directly
            pub = publisherSession.getPublisher(internalAdmin, name);
            assertEquals("bar", pub.getDescription());
            // Flush caches to reset cache timeout
            publisherSession.flushPublisherCache();
            /// Read publisher to ensure it is in cache
            pub = publisherSession.getPublisher(internalAdmin, name);
            assertEquals("bar", pub.getDescription());
            // Change publisher not flushing cache, old value should remain when reading
            pub.setDescription("newvalue");
            publisherSession.internalChangeCertificateProfileNoFlushCache(internalAdmin, name, pub);
            pub = publisherSession.getPublisher(internalAdmin, name);
            assertEquals("bar", pub.getDescription()); // old value
            // Wait 2 seconds and try again, now the cache should have been updated
            Thread.sleep(2000);
            pub = publisherSession.getPublisher(internalAdmin, name);
            assertEquals("newvalue", pub.getDescription()); // new value
        } finally {
            configSession.updateProperty("publisher.cachetime", oldcachetime);
            publisherSession.removePublisher(internalAdmin, name);
        }
    } 

}
