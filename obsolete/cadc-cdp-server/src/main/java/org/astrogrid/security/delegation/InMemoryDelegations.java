/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2010.                            (c) 2010.
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 *
 * @author adriand
 * 
 * @version $Revision: $
 * 
 * 
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package org.astrogrid.security.delegation;


import ca.nrc.cadc.cred.CertUtil;

import java.io.IOException;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
/**
 * A collection of delegated credentials. For each key there is a private key,
 * a certificate-signing request (CSR) and, optionally, a certificate.
 * <p>
 * This class is thread safe. Initializing an identity is idempotent. The
 * name, keys and CSR for each identity are immutable, and access to the
 * certificate is synchronized. Further, the class will reject an attempt
 * to set a certificate whose public key does not match that set for the
 * identity at initialization; therefore, if two threads delegate to the
 * same identity concurrently, the credentials held are not disrupted.
 *
 * @author Guy Rixon
 */

public class InMemoryDelegations extends Delegations
{

    

    /**
     * All the delegations, partial or complete, known to this
     * object. The key-pairs for delegated credentials live here.
     * The keys are hashes of the delegated principals: see
     * {@link #hash} for details.
     */
    private Map<String, DelegatedIdentity> identities;

    private KeyPairGenerator keyPairGenerator;
    
    /**
     * Constructs a Delegations object.
     */
    protected InMemoryDelegations() {
      
      // Add the Bouncy Castle JCE provider. This allows the CSR
      // classes to work. The BC implementation of PKCS#10 depends on
      // the ciphers in the BC provider.
      if (Security.getProvider("BC") == null) {
        Security.addProvider(new BouncyCastleProvider());
      }
      
      erase();

      try {
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      } catch (NoSuchAlgorithmException ex) {
        ex.printStackTrace();
        throw new RuntimeException("The JCE doesn't do RSA! Game over.");
      }
      keyPairGenerator.initialize(CertUtil.DEFAULT_KEY_LENGTH);
    }
    

    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#erase()
   */
    public void erase() {
      identities = new ConcurrentHashMap<String, DelegatedIdentity>();
    }


    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#initializeIdentity(java.lang.String)
   */
    public String initializeIdentity(String identity) throws GeneralSecurityException {
      X500Principal p = new X500Principal(identity);
      return initializeIdentity(p);
    }
    
    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#initializeIdentity(javax.security.auth.x500.X500Principal)
   */
    public String initializeIdentity(X500Principal principal) throws GeneralSecurityException {
      String hashKey = hash(principal);
      if (!identities.containsKey(hashKey)) {
        DelegatedIdentity id = 
            new DelegatedIdentity(principal.getName(X500Principal.CANONICAL),
                                  this.keyPairGenerator.generateKeyPair());
        identities.put(hashKey, id);
      }
      return hashKey;
    }
    
    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#getCsr(java.lang.String)
   */
  public CertificateSigningRequest getCsr(String hashKey) {
      DelegatedIdentity id = identities.get(hashKey);
      return (id == null)? null : id.csr;
    }
    
    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#getPrivateKey(java.lang.String)
   */
  public PrivateKey getPrivateKey(String hashKey) { 
      DelegatedIdentity id = identities.get(hashKey);
      return (id == null)? null: (PrivateKey) id.keys.getPrivate();
    }
    
    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#getCertificate(java.lang.String)
   */
    public X509Certificate[] getCertificates(String hashKey)
    {
        DelegatedIdentity id = identities.get(hashKey);
        if (id == null)
        {
            return null;
        }
        else
        {
            synchronized (id)
            {
                return new X509Certificate[] { id.certificate };
            }
        }
    }
    
    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#remove(java.lang.String)
   */
  public void remove(String hashKey) {
      identities.remove(hashKey);
    }
    
    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#isKnown(java.lang.String)
   */
    public boolean isKnown(String hashKey) {
      return identities.containsKey(hashKey);
    }
    
    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#setCertificate(java.lang.String, java.security.cert.X509Certificate)
   */
    public void setCertificates(String          hashKey,
                               X509Certificate[] certificates) throws InvalidKeyException {
      DelegatedIdentity id = identities.get(hashKey);
      if (id == null) {
        throw new InvalidKeyException("No identity matches the hash key " + hashKey);
      } else {
        id.setCertificate(certificates[0]);
      }
    }
    
    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#getPrincipals()
   */
  public Object[] getPrincipals() {
      return identities.keySet().toArray();
    }
    
    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#getName(java.lang.String)
   */
  public String getName(String hashKey) {
      DelegatedIdentity id = identities.get(hashKey);
      return (id == null)? null : id.dn;
    }

    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#getKeys(java.lang.String)
   */
    public KeyPair getKeys(String hashKey) {
      DelegatedIdentity id = identities.get(hashKey);
      return (id == null)? null : id.getKeys();
    }
    
    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#writeCertificate(java.lang.String, java.io.Writer)
     */
    public void writeCertificate(String hashKey, Writer out) throws IOException {
      PEMWriter pem = new PEMWriter(out);
      for (X509Certificate cert : getCertificates(hashKey))
      {
          pem.writeObject(cert);
      }
      pem.flush();
      pem.close();
    }
    
    /* (non-Javadoc)
   * @see org.astrogrid.security.delegation.Delegations#hasCertificate(java.lang.String)
   */
    public boolean hasCertificate(String hashKey) {
        X509Certificate[] certs = this.getCertificates(hashKey); 
      return ( certs != null && certs.length > 0);
    }

    
    protected class DelegatedIdentity {
      protected final String                    dn;
      protected final KeyPair                   keys;
      protected final CertificateSigningRequest csr;
      protected X509Certificate                 certificate;

      protected DelegatedIdentity(String  dn,
                                  KeyPair keys) throws GeneralSecurityException {
        this.dn          = dn;
        this.keys        = keys;
        this.csr         = new CertificateSigningRequest(dn, keys);
        this.certificate = null;
      }

      protected synchronized X509Certificate getCertificate() {
        return certificate;
      }

      protected synchronized void setCertificate(X509Certificate c) throws InvalidKeyException {
        if (c.getPublicKey().equals(keys.getPublic())) {
          certificate = c;
        }
        else {
          throw new InvalidKeyException("This certificate does not match the cached private-key.");
        }
      }

      protected KeyPair getKeys() {
        return keys;
      }

    }
    

    
    

}