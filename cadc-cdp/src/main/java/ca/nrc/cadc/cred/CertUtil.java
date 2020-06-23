/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2020.                            (c) 2020.
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
*  $Revision: 5 $
*
************************************************************************
*/

package ca.nrc.cadc.cred;

import ca.nrc.cadc.auth.X509CertificateChain;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;
import java.util.TimeZone;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

/**
 * Utilities for certificate operations
 */
public class CertUtil
{
    
    public static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256WITHRSA";
    
    public static final int DEFAULT_KEY_LENGTH = 2048;

    /**
     * Method that generates an X509 proxy certificate
     * 
     * @param csr CSR for the certificate
     * @param lifetime lifetime of the certificate in SECONDS
     * @param chain certificate used to sign the proxy certificate
     * @return generated proxy certificate
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws CertificateParsingException
     * @throws CertificateEncodingException
     * @throws SignatureException
     * @throws CertificateNotYetValidException
     * @throws CertificateExpiredException
     */
    public static X509Certificate generateCertificate(PKCS10CertificationRequest csr, 
            int lifetime, X509CertificateChain chain) 
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            CertificateParsingException, CertificateEncodingException,
            SignatureException, CertificateExpiredException,
            CertificateNotYetValidException
    {
        X509Certificate issuerCert = chain.getChain()[0];
        PrivateKey issuerKey = chain.getPrivateKey();

        Security.addProvider(new BouncyCastleProvider());

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System
                .currentTimeMillis()));
        certGen.setIssuerDN(issuerCert.getSubjectX500Principal());

        // generate the proxy DN as the issuerDN + CN=random number
        Random rand = new Random();
        String issuerDN = issuerCert.getSubjectX500Principal().getName(
                X500Principal.RFC2253);
        String delegDN = String.valueOf(Math.abs(rand.nextInt()));
        String proxyDn = "CN=" + delegDN + "," + issuerDN;
        certGen.setSubjectDN(new X500Principal(proxyDn));

        // set validity
        GregorianCalendar date = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        // Start date. Allow for a sixty five minute clock skew here.
        date.add(Calendar.MINUTE, -65);
        Date beforeDate = date.getTime();
        for (X509Certificate currentCert : chain.getChain())
        {
            if (beforeDate.before(currentCert.getNotBefore()))
            {
                beforeDate = currentCert.getNotBefore();
            }
        }
        certGen.setNotBefore(beforeDate);

        // End date.
        // If hours = 0, then cert lifetime is set to that of user cert
        if (lifetime <= 0)
        {
            // set the validity of certificates as the minimum
            // of the certificates in the chain
            Date afterDate = issuerCert.getNotAfter();
            for (X509Certificate currentCert : chain.getChain())
            {
                if (afterDate.after(currentCert.getNotAfter()))
                {
                    afterDate = currentCert.getNotAfter();
                }
            }
            certGen.setNotAfter(afterDate);
        }
        else
        {
            // check the validity of the signing certificate
            date.add(Calendar.MINUTE, 5);
            date.add(Calendar.SECOND, lifetime);
            for (X509Certificate currentCert : chain.getChain())
            {
                currentCert.checkValidity(date.getTime());
            }

            certGen.setNotAfter(date.getTime());
        }

        certGen.setPublicKey(csr.getPublicKey());
        // TODO: should be able to get signature algorithm from the csr, but... obtuse
        certGen.setSignatureAlgorithm(DEFAULT_SIGNATURE_ALGORITHM);

        // extensions
        // add ProxyCertInfo extension to the new cert

        certGen.addExtension(X509Extensions.KeyUsage, true, 
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier,
            false, new AuthorityKeyIdentifierStructure(issuerCert));

        certGen.addExtension(X509Extensions.SubjectKeyIdentifier,
            false, new SubjectKeyIdentifierStructure(csr.getPublicKey("BC")));

        certGen.addExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(false));

        // add the Proxy Certificate Information
        // I expect this code to be removed once support to proxy
        // certificates is provided in Bouncy Castle.

        // create a proxy policy
        // types of proxy certificate policies - see RFC3820
        // impersonates the user
        final DERObjectIdentifier IMPERSONATION = new DERObjectIdentifier(
                "1.3.6.1.5.5.7.21.1");
        // independent
        // final DERObjectIdentifier INDEPENDENT = new
        // DERObjectIdentifier(
        // "1.3.6.1.5.5.7.21.2");
        // defined by a policy language
        // final DERObjectIdentifier LIMITED = new DERObjectIdentifier(
        // "1.3.6.1.4.1.3536.1.1.1.9");

        ASN1EncodableVector policy = new ASN1EncodableVector();
        policy.add(IMPERSONATION);

        // pathLengthConstr (RFC3820)
        // The pCPathLenConstraint field, if present, specifies the
        // maximum
        // depth of the path of Proxy Certificates that can be signed by
        // this
        // Proxy Certificate. A pCPathLenConstraint of 0 means that this
        // certificate MUST NOT be used to sign a Proxy Certificate. If
        // the
        // pCPathLenConstraint field is not present then the maximum proxy
        // path
        // length is unlimited. End entity certificates have unlimited
        // maximum
        // proxy path lengths.
        // DERInteger pathLengthConstr = new DERInteger(100);

        // create the proxy certificate information
        ASN1EncodableVector vec = new ASN1EncodableVector();
        // policy.add(pathLengthConstr);
        vec.add(new DERSequence(policy));

        // OID
        final DERObjectIdentifier OID = new DERObjectIdentifier(
                "1.3.6.1.5.5.7.1.14");
        certGen.addExtension(OID, true, new DERSequence(vec));

        return certGen.generate(issuerKey, "BC");
    }

    /**
     * @param chain certificate
     * @param writer writer use to write the generated PEM certificate
     * @throws IOException
     */
    public static void writePEMCertificateAndKey(
            X509CertificateChain chain, Writer writer)
            throws IOException
    {
        if (chain == null)
            throw new IllegalArgumentException("Null certificate chain");
        if (writer == null)
            throw new IllegalArgumentException("Null writer");

        PEMWriter pemWriter = new PEMWriter(writer);
        // write the first certificate first
        pemWriter.writeObject(chain.getChain()[0]);
        // then the key
        pemWriter.writeObject(chain.getPrivateKey());
        // and finally the rest of the certificates in the chain
        for (int i = 1; i < chain.getChain().length; i++)
        {
            pemWriter.writeObject(chain.getChain()[i]);
        }        
        pemWriter.flush();
    }
}
