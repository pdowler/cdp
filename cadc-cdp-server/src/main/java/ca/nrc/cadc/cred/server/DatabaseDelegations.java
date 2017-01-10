/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2009.                            (c) 2009.
*  Government of Canada                 Gouvernement du Canada
*  National Research Council            Conseil national de recherches
*  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
*  All rights reserved                  Tous droits réservés
*                                       
*  NRC disclaims any warranties,        Le CNRC dénie toute garantie
*  expressed, implied, or               énoncée, implicite ou légale,
*  statutory, of any kind with          de quelque nature que ce
*  respect to the software,             soit, concernant le logiciel,
*  including without limitation         y compris sans restriction
*  any warranty of merchantability      toute garantie de valeur
*  or fitness for a particular          marchande ou de pertinence
*  purpose. NRC shall not be            pour un usage particulier.
*  liable in any event for any          Le CNRC ne pourra en aucun cas
*  damages, whether direct or           être tenu responsable de tout
*  indirect, special or general,        dommage, direct ou indirect,
*  consequential or incidental,         particulier ou général,
*  arising from the use of the          accessoire ou fortuit, résultant
*  software.  Neither the name          de l'utilisation du logiciel. Ni
*  of the National Research             le nom du Conseil National de
*  Council of Canada nor the            Recherches du Canada ni les noms
*  names of its contributors may        de ses  participants ne peuvent
*  be used to endorse or promote        être utilisés pour approuver ou
*  products derived from this           promouvoir les produits dérivés
*  software without specific prior      de ce logiciel sans autorisation
*  written permission.                  préalable et particulière
*                                       par écrit.
*                                       
*  This file is part of the             Ce fichier fait partie du projet
*  OpenCADC project.                    OpenCADC.
*                                       
*  OpenCADC is free software:           OpenCADC est un logiciel libre ;
*  you can redistribute it and/or       vous pouvez le redistribuer ou le
*  modify it under the terms of         modifier suivant les termes de
*  the GNU Affero General Public        la “GNU Affero General Public
*  License as published by the          License” telle que publiée
*  Free Software Foundation,            par la Free Software Foundation
*  either version 3 of the              : soit la version 3 de cette
*  License, or (at your option)         licence, soit (à votre gré)
*  any later version.                   toute version ultérieure.
*                                       
*  OpenCADC is distributed in the       OpenCADC est distribué
*  hope that it will be useful,         dans l’espoir qu’il vous
*  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
*  without even the implied             GARANTIE : sans même la garantie
*  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
*  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
*  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
*  General Public License for           Générale Publique GNU Affero
*  more details.                        pour plus de détails.
*                                       
*  You should have received             Vous devriez avoir reçu une
*  a copy of the GNU Affero             copie de la Licence Générale
*  General Public License along         Publique GNU Affero avec
*  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
*  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
*                                       <http://www.gnu.org/licenses/>.
*
*  $Revision: 4 $
*
************************************************************************
*/

package ca.nrc.cadc.cred.server;

import java.io.IOException;
import java.io.Writer;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.CertUtil;
import org.apache.log4j.Logger;
import org.astrogrid.security.delegation.CertificateSigningRequest;
import org.astrogrid.security.delegation.Delegations;
import org.astrogrid.security.delegation.Util;

/**
 * Implementation of the base Delegations that stores certificates in a 
 * relational database.
 * 
 * @author pdowler
 */
public class DatabaseDelegations extends Delegations
{
    private static final Logger log = Logger.getLogger(DatabaseDelegations.class);
    
    private CertificateDAO certificateDAO = null;
    private KeyPairGenerator keyPairGenerator;
    
    protected DatabaseDelegations(String dataSourceName, CertificateDAO.CertificateSchema config)
    {
        // Add the Bouncy Castle JCE provider. This allows the CSR
        // classes to work. The BC implementation of PKCS#10 depends on
        // the ciphers in the BC provider.
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try
        {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(CertUtil.DEFAULT_KEY_LENGTH);
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new RuntimeException("BUG/CONFIG: cannot load RSA key-pair generator", ex);
        }
        
        certificateDAO = new CertificateDAO(config);
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#initializeIdentity(java.lang.String)
     */
    @Override
    public String initializeIdentity(String identity) throws GeneralSecurityException
    {
        try
        {
            String canonizedDn = AuthenticationUtil.canonizeDistinguishedName(identity);
            X500Principal p = new X500Principal(canonizedDn);
            return initializeIdentity(p);
        }
        catch(GeneralSecurityException gex)
        {
            log.debug("initializeIdentity failed", gex);
            throw gex;
        }
        catch(RuntimeException t)
        {
            log.debug("initializeIdentity failed", t);
            throw t;
        }
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#initializeIdentity(javax.security.auth.x500.X500Principal)
     */
    @Override
    public String initializeIdentity(X500Principal principal) throws GeneralSecurityException
    {
        try
        {
            String canonizedDn = AuthenticationUtil.canonizeDistinguishedName(principal.getName());
            X500Principal p = new X500Principal(canonizedDn);
            String hashKey = hash(p);
            KeyPair keyPair = this.keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            log.debug("creating CertificateSigningRequest: " + canonizedDn + "," + keyPair);
            CertificateSigningRequest csr = new CertificateSigningRequest(canonizedDn, keyPair);

            X509CertificateChain chain = new X509CertificateChain(p, privateKey, Util.getCsrString(csr));

            certificateDAO.put(chain);
            return hashKey;
        }
        catch(GeneralSecurityException gex)
        {
            log.debug("initializeIdentity failed", gex);
            throw gex;
        }
        catch(RuntimeException t)
        {
            log.debug("initializeIdentity failed", t);
            throw t;
        }
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getCsr(java.lang.String)
     */
    @Override
    public CertificateSigningRequest getCsr(String hashKey)
    {
        X509CertificateChain x509CertificateChain = certificateDAO.get(hashKey);
        if (x509CertificateChain == null)
        {
            return null;
        }
        String csrString = x509CertificateChain.getCsrString();
        CertificateSigningRequest csr = Util.getCsrFromString(csrString);
        return csr;
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getPrivateKey(java.lang.String)
     */
    @Override
    public PrivateKey getPrivateKey(String hashKey)
    {
        X509CertificateChain x509CertificateChain = certificateDAO.get(hashKey);
        if (x509CertificateChain == null)
        {
            return null;
        }
        return x509CertificateChain.getPrivateKey();
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getCertificate(java.lang.String)
     */
    @Override
    public X509Certificate[] getCertificates(String hashKey)
    {
        X509CertificateChain x509CertificateChain = certificateDAO.get(hashKey);
        if (x509CertificateChain == null)
        {
            return null;
        }
        return x509CertificateChain.getChain();
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#remove(java.lang.String)
     */
    @Override
    public void remove(String hashKey)
    {
        certificateDAO.delete(hashKey);
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#isKnown(java.lang.String)
     */
    @Override
    public boolean isKnown(String hashKey)
    {
        X509CertificateChain chain = certificateDAO.get(hashKey);
        return (chain != null);
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#setCertificate(java.lang.String, java.security.cert.X509Certificate)
     */
    @Override
    public void setCertificates(String hashKey, X509Certificate[] certificates) throws InvalidKeyException
    {
        X509CertificateChain chain = certificateDAO.get(hashKey);
        if (chain != null)
        {
            chain.setChain(certificates);
            certificateDAO.put(chain);
        }
        else
            throw new InvalidKeyException("No identity matches the hash key " + hashKey);
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getPrincipals()
     */
    @Override
    public Object[] getPrincipals()
    {
//        List<String> hashKeyList = certificateDAO.getAllHashKeys();
//        return hashKeyList.toArray();
        //TODO AD: this is a workaround to send the hash to the caller when it
        // does a listing.
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);
        Set<X500Principal> principals = subject
                .getPrincipals(X500Principal.class);
        if (principals.size() == 0)
        {
            throw new AccessControlException(
                    "Delegation failed because the caller is not authenticated.");
        }
        else if (principals.size() > 1)
        {
            throw new AccessControlException(
                    "Delegation failed because caller autheticated with multiple certificates.");
        }
        return new String[] { X509CertificateChain.genHashKey(principals
                .iterator().next()) };
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getName(java.lang.String)
     */
    @Override
    public String getName(String hashKey)
    {
        X509CertificateChain x509CertificateChain = certificateDAO.get(hashKey);
        if (x509CertificateChain == null)
        {
            return null;
        }
        String dn = x509CertificateChain.getPrincipal().getName();
        return dn;
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getKeys(java.lang.String)
     */
    @Override
    public KeyPair getKeys(String hashKey)
    {
        throw new RuntimeException("getKeys() not implemented in DAO version implementation."); 
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#hasCertificate(java.lang.String)
     */
    @Override
    public boolean hasCertificate(String hashKey)
    {
        X509CertificateChain chain = certificateDAO.get(hashKey);
        return (chain.getChain() != null);
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#writeCertificate(java.lang.String, java.io.Writer)
     */
    @Override
    public void writeCertificate(String hashKey, Writer out) throws IOException
    {
        PEMWriter pem = new PEMWriter(out);
        X509Certificate[] certs = getCertificates(hashKey);
        if (certs == null)
        {
            throw new IllegalArgumentException(
                    "No certificate corresponding to the haskey: " + hashKey);
        }
        for (X509Certificate cert : certs)
        {
            pem.writeObject(cert);
        }
        pem.flush();
        pem.close();
    }
}
