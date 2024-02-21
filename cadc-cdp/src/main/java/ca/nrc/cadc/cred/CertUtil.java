/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2023.                            (c) 2023.
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

import ca.nrc.cadc.auth.AuthenticationUtil;
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
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Random;
import java.util.TimeZone;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * Utilities for certificate operations
 */
public class CertUtil {
    private static final Logger log = Logger.getLogger(CertUtil.class);
    
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
            CertificateNotYetValidException {

        X509Certificate issuerCert = chain.getChain()[0];
        final PrivateKey issuerKey = chain.getPrivateKey();
        Security.addProvider(new BouncyCastleProvider());
        
        final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        final X500Name issuer = flipDN(issuerCert.getSubjectX500Principal().toString());
        log.debug("issuer: " + issuer);
        
        // generate the proxy DN as the issuerDN with additional CN=random number
        Random rand = new Random();
        String issuerDN = issuerCert.getSubjectX500Principal().getName(X500Principal.RFC2253); // CN on the left
        String delegCN = String.valueOf(Math.abs(rand.nextInt()));
        String proxyDN = "CN=" + delegCN + "," + issuerDN;
        log.debug("proxyDN: " + proxyDN);
        final X500Name subject = flipDN(proxyDN);
        log.debug("x500name of subject: " + subject);
        
        // start date
        GregorianCalendar date = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        // Start date. Allow for a sixty five minute clock skew here.
        date.add(Calendar.MINUTE, -65);
        Date beforeDate = date.getTime();
        for (X509Certificate currentCert : chain.getChain()) {
            if (beforeDate.before(currentCert.getNotBefore())) {
                beforeDate = currentCert.getNotBefore();
            }
        }

        // end date
        // If hours = 0, then cert lifetime is set to that of user cert
        date = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        Date afterDate = date.getTime();
        if (lifetime <= 0) {
            // set the validity of certificates as the minimum
            // of the certificates in the chain
            afterDate = issuerCert.getNotAfter();
            for (X509Certificate currentCert : chain.getChain()) {
                if (afterDate.after(currentCert.getNotAfter())) {
                    afterDate = currentCert.getNotAfter();
                }
            }
        } else {
            // check the validity of the signing certificate
            date.add(Calendar.MINUTE, 5);
            date.add(Calendar.SECOND, lifetime);
            for (X509Certificate currentCert : chain.getChain()) {
                currentCert.checkValidity(date.getTime());
            }
            afterDate = date.getTime();
        }

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(issuer,
                serial, beforeDate, afterDate, subject, csr.getSubjectPublicKeyInfo());

        
        // extensions
        // add ProxyCertInfo extension to the new cert
        try {
            BcDigestCalculatorProvider dcp = new BcDigestCalculatorProvider();
            DigestCalculator dc = dcp.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)); // RFC 5280
            X509ExtensionUtils x509ext = new X509ExtensionUtils(dc);

            certGen.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).getEncoded());

            certGen.addExtension(Extension.authorityKeyIdentifier, false, 
                    x509ext.createAuthorityKeyIdentifier(csr.getSubjectPublicKeyInfo()));

            certGen.addExtension(Extension.subjectKeyIdentifier, false, 
                    x509ext.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

            certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded());
        } catch (IOException | OperatorCreationException ex) {
            throw new RuntimeException("failed to add X509 extensions", ex);
        }
        
        // add the Proxy Certificate Information
        // I expect this code to be removed once support to proxy
        // certificates is provided in Bouncy Castle.
        // create a proxy policy
        // types of proxy certificate policies - see RFC3820
        // impersonates the user
        final ASN1ObjectIdentifier IMPERSONATION = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.21.1");
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
        final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.14");
        try {
            certGen.addExtension(OID, true, new DERSequence(vec));
        } catch (CertIOException ex) {
            throw new RuntimeException("failed to add X509 proxy extension", ex);
        }

        try {
            ContentSigner signer = new JcaContentSignerBuilder(DEFAULT_SIGNATURE_ALGORITHM).setProvider("BC").build(issuerKey);
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");
        
            return converter.getCertificate(certGen.build(signer));
        } catch (CertificateException | OperatorCreationException ex) {
            throw new RuntimeException("failed to create+sign proxy cert", ex);
        }
    }
    
    private static X500Name flipDN(String sdn) {
        try {
            LdapName dn = new LdapName(sdn);
            List<Rdn> rdns = dn.getRdns();
            StringBuilder sb = new StringBuilder();
            for (Rdn r : rdns) {
                // writing in normal order is actually flipping LDAP order
                sb.append(r.toString());
                sb.append(",");
            }
            return new X500Name(sb.substring(0, sb.length() - 1)); // strip off comma-space
        } catch (InvalidNameException ex) {
            throw new RuntimeException("BUG: failed to flip DN", ex);
        }
    }

    /**
     * @param chain certificate
     * @param writer writer use to write the generated PEM certificate
     * @throws IOException
     */
    public static void writePEMCertificateAndKey(
            X509CertificateChain chain, Writer writer)
            throws IOException {
        if (chain == null) {
            throw new IllegalArgumentException("Null certificate chain");
        }
        if (writer == null) {
            throw new IllegalArgumentException("Null writer");
        }

        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        // write the first certificate first
        pemWriter.writeObject(chain.getChain()[0]);
        // then the key
        pemWriter.writeObject(chain.getPrivateKey());
        // and finally the rest of the certificates in the chain
        for (int i = 1; i < chain.getChain().length; i++) {
            pemWriter.writeObject(chain.getChain()[i]);
        }
        pemWriter.flush();
    }
}
