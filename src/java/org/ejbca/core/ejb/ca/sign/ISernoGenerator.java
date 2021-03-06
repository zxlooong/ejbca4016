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
 
package org.ejbca.core.ejb.ca.sign;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;


/**
 * Interface for a serial number generator.
 *
 * @version $Id: ISernoGenerator.java 8373 2009-11-30 14:07:00Z jeklund $
 */
public interface ISernoGenerator {
    /**
     * Generates a number of serial number bytes.
     *
     * @return an array of serial number bytes.
     */
    public BigInteger getSerno();

    /**
     * Returns the number of serial number bytes generated by this generator.
     *
     * @return The number of serial number bytes generated by this generator.
     */
    public int getNoSernoBytes();

    /**
     * Sets an optional seed needed by the serno generator. This can be different things, for a
     * sequential generator it can for instance be the first number to be generated and for a
     * random generator it can be a random seed. The constructor may seed the generator enough so
     * this method may not be nessecary to call.
     *
     * @param the seed used to initilize the serno generator.
     */
    public void setSeed(long seed);
    
    /** 
     * Set the algorithm used for the serial number generator, if needed to set.
     * Usually a default value is provided for your serial number generator. 
     * This can be used to override default values. 
     * @param an (optional) algorithm for a serial number generator implementation
     */
     public void setAlgorithm(String algo) throws NoSuchAlgorithmException;
     
     /** 
      * Sets the desired length of serial number returned by the generator. 
      * The generator should have a default value, which could be overridden though.
      * @param the size of the requested serial numbers in octets, i.e. 8, 4, ...
      */
     public void setSernoOctetSize(int noOctets);

}
