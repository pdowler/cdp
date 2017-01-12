/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2011.                            (c) 2011.
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

package ca.nrc.cadc.cert;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.CertUtil;
import ca.nrc.cadc.cred.client.CredClient;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.util.ArgumentMap;
import java.net.URI;
import java.security.spec.InvalidKeySpecException;

/**
 * Generates a new certificate using CDP client API.
 * 
 * @author pdowler
 */
public class CertGenAction extends DbCertGenAction
{
    private static final Logger LOGGER = Logger.getLogger(CertGenAction.class);
    private int lifetime = 365; // 365 days

    // CADC specific fields of the DN
    public static final String CADC_DN = "ou=cadc,o=hia,c=ca";


    // Certificate of the signing authority
    X509CertificateChain signer;
    boolean dryRun = true;

    public CertGenAction(URI serviceID)
    {
        super(serviceID);
    }
    
    @Override
    public boolean init(final ArgumentMap argMap) throws IOException
    {
        if (!super.init(argMap))
            return false;

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        String signingKeyStr = argMap.getValue(Main.ARG_SIGNED_CERT);
        if (signingKeyStr == null)
        {
            LOGGER.error(Main.ARG_SIGNED_CERT
                         + " argument missing");
            return false;
        }


        File signingKeyFile = new File(signingKeyStr);
        try
        {
            this.signer = SSLUtil.readPemCertificateAndKey(signingKeyFile);
        }
        catch (Exception ex)
        {
            throw new RuntimeException("failed to read "
                                       + Main.ARG_SIGNED_CERT + " " + signingKeyStr, ex);
        }

        dryRun = argMap.isSet(Main.ARG_DRYRUN);

        return super.init(argMap);
    }

    @Override
    protected void runCommand() throws Exception
    {
        LOGGER.debug("Entering generateCertificate");
        boolean result = true;

        if (userid != null)
        {
            // create a cert for a single user
            HttpPrincipal useridPrincipal = new HttpPrincipal(userid);
            X500Principal userDN = super.getCertificateDN(useridPrincipal);
            LOGGER.debug("About to create certificate for user " + userid + " with DN " + userDN.toString());
            generateCertificate(userDN);
            msg("New user DN: " + userDN.toString());
        }
        else
        {
            // renew certs for all users who's are about to expire
            int count = 0;
            X500Principal[] userDNs = getExpiring(super.expiring);
            if (dryRun)
            {
                for (X500Principal userDN : userDNs)
                {
                    msg("expiring: " + userDN.getName());
                }
                count = (userDNs == null ? 0 : userDNs.length);
                msg("Found " + count + " certificates that will expire " +
                    "within " + super.expiring + " days.");
            }
            else
            {
                for (X500Principal userDN : userDNs)
                {
                    try
                    {
                        generateCertificate(userDN);
                    }
                    catch (Exception e)
                    {

                    }
                    count++;
                }
                msg("Renewed " + count + " certificates");
            }
        }
    }

    /**
     * Generates a certificate signed with subject's credentials (CADC private
     * key) and persists them.
     *
     * @param userDN The X500Principal to generate for.
     * @return X509CertificateChain generated and signed certificate chain
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws IllegalStateException
     * @throws IOException
     * @throws CertificateException
     * @throws CertificateNotYetValidException
     * @throws CertificateExpiredException
     */
    private void generateCertificate(final X500Principal userDN)
            throws NoSuchAlgorithmException, InvalidKeyException,
                   NoSuchProviderException, SignatureException,
                   IllegalStateException, CertificateException, IOException,
                   ResourceNotFoundException
    {

        if (!AuthenticationUtil.canonizeDistinguishedName(
                userDN.getName()).contains(CADC_DN))
        {
            throw new IllegalArgumentException(
                    "Wrong o, ou, or c fields in user DN: " + userDN);
        }

        LOGGER.debug("Generate private key & CSR");

        CredClient client = new CredClient(serviceID);
        try
        {
            client.deleteResource(userDN); // remove old CSR
        }
        catch (ResourceNotFoundException ignore)
        {
        }

        client.createResoure(userDN);  // generate a new CSR with current specs
        String encodedCSR = client.getEncodedCSR(userDN);

        if (encodedCSR == null)
        {
            // shouldn't happen
            throw new RuntimeException("No corresponding CSR found on the server");
        }

        PEMReader reader = new PEMReader(new StringReader(encodedCSR));
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) reader
                .readObject();

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));

        //certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setIssuerDN(signer.getPrincipal());
        certGen.setSubjectDN(userDN);

        // set validity
        GregorianCalendar date = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        date.add(Calendar.MINUTE, -5); // Allow for a five minute clock
        // skew here.
        certGen.setNotBefore(date.getTime());
        // If hours = 0, then cert lifetime is set to that of user cert
        date.add(Calendar.MINUTE, 5);
        date.add(Calendar.HOUR, lifetime * 24);
        certGen.setNotAfter(date.getTime());

        certGen.setPublicKey(csr.getPublicKey());
        certGen.setSignatureAlgorithm(CertUtil.DEFAULT_SIGNATURE_ALGORITHM);
        //certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
        //        new AuthorityKeyIdentifierStructure(caCert));
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                             new AuthorityKeyIdentifierStructure(signer.getChain()[0]));
        // no extensions, at least for now
        LOGGER.debug("Generate certificate");
        //X509Certificate cert = certGen.generate(signingKey, "BC");
        X509Certificate cert = certGen.generate(signer.getPrivateKey(), "BC");

        // build chain with all but the last cert (assumed to be a CA)
        // if signer is the CA, this creates a [1] and for loop does nothing
        X509Certificate[] chain = new X509Certificate[signer.getChain().length];
        chain[0] = cert;
        System.arraycopy(signer.getChain(), 0, chain, 1,
                         signer.getChain().length - 1);

        LOGGER.debug("Persisting certificate for " + userDN
                .getName() + " chain length: " + chain.length);

        client.putSignedCert(chain);
        String dn = userDN.getName();
        String noWhitespaceDN = dn.replaceAll("\\s","");
        msg("Generated certificate for " + noWhitespaceDN);
    }


}
