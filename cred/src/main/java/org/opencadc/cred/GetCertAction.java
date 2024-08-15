/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2024.                            (c) 2024.
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
 ************************************************************************
 */

package org.opencadc.cred;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.CertUtil;
import ca.nrc.cadc.rest.InlineContentHandler;
import ca.nrc.cadc.rest.RestAction;
import ca.nrc.cadc.util.StringUtil;
import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.AccessControlException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Set;
import java.util.TimeZone;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Class to handle certificate generation requests
 * @author adriand
 */
public class GetCertAction extends RestAction {
    protected static Logger log = Logger.getLogger(GetCertAction.class);

    static final String CERTIFICATE_CONTENT_TYPE = "application/x-pem-file";
    static final String CERTIFICATE_FILENAME = "cadcproxy.pem"; // content disposition
    static final int CERT_KEY_SIZE = 2048;

    // CADC specific fields of the DN
    public static final String CADC_DN = "ou=cadc,o=hia,c=ca";

    private CredConfig config;

    public GetCertAction() {
        super();
    }

    @Override
    protected final InlineContentHandler getInlineContentHandler() {
        return null;
    }

    @Override
    public void initAction() {
        config = CredInitAction.getConfig(super.appName);
    }

    @Override
    public void doAction() throws Exception {
        // create a cert for a single user
        Subject caller = AuthenticationUtil.getCurrentSubject();
        String path = syncInput.getPath();
        if (AuthMethod.CERT.equals(AuthenticationUtil.getAuthMethod(caller)) && !StringUtil.hasText(path)) {
            throw new AccessControlException("Cert Authentication not allowed for cert renewal.");
        }
        Set<X500Principal> dnPrincipals = caller.getPrincipals(X500Principal.class);
        if (dnPrincipals.size() != 1) {
            throw new NotAuthenticatedException("Authentication required (caller DN not found).");
        }
        X500Principal callerDN = dnPrincipals.iterator().next();


        X500Principal userDN = callerDN;
        if (StringUtil.hasText(path)) {
            path = path.replace("^/+", "").replace("/+$", "");
            log.debug("User ID path " + path);
            Principal delegatedUser = getPrincipal(path);
            if (config.superUsers.contains(callerDN)) {
                if (delegatedUser instanceof X500Principal) {
                    // no need for augment subject
                    userDN = (X500Principal)delegatedUser;
                } else {
                    Subject delegatedSub = new Subject();
                    delegatedSub.getPrincipals().add(delegatedUser);
                    AuthenticationUtil.augmentSubject(delegatedSub);
                    dnPrincipals = delegatedSub.getPrincipals(X500Principal.class);
                    if (dnPrincipals.size() != 1) {
                        throw new NotAuthenticatedException("User not found: " + delegatedUser);
                    }
                    userDN = dnPrincipals.iterator().next();
                }
            } else {
                throw new AccessControlException("Not a superuser: " + callerDN);
            }
        }
        float daysValid = config.maxDaysValid;
        String daysValidStr = syncInput.getParameter("daysValid");
        log.debug("daysValid: " + daysValidStr);

        if (daysValidStr != null) {
            try {
                daysValid = Float.parseFloat(daysValidStr);
                if (daysValid > config.maxDaysValid) {
                    throw new IllegalArgumentException("daysValid larger than maximum allowed: " + config.maxDaysValid);
                }
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("daysValid is not a float: " + daysValidStr);
            }
        }
        String canonizedDN = AuthenticationUtil.canonizeDistinguishedName(userDN.getName());
        X500Name userName = new X500Name(canonizedDN);

        // Generate key pair
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        rsaGenerator.initialize(CERT_KEY_SIZE, random);
        KeyPair keyPair = rsaGenerator.generateKeyPair();

        X509CertificateChain signer = SSLUtil.readPemCertificateAndKey(new File(config.signingCert));
        log.debug("About to create certificate for user with DN " + userName);
        X509Certificate cert = generateCertificate(userName, keyPair.getPublic(), signer, daysValid);

        setResponseHeaders();
        // write new certificate, new certificate private key, signing cert chain
        JcaPEMWriter pw = new JcaPEMWriter(new OutputStreamWriter(syncOutput.getOutputStream()));
        pw.writeObject(cert);
        pw.writeObject(keyPair.getPrivate());
        for (X509Certificate x509Certificate : signer.getChain()) {
            pw.writeObject(x509Certificate);
        }
        pw.flush();
    }

    private void setResponseHeaders() {
        syncOutput.setHeader("Content-Disposition", "inline; filename=\"" + CERTIFICATE_FILENAME + "\"");
        syncOutput.setHeader("Content-Type", CERTIFICATE_CONTENT_TYPE);
        syncOutput.setCode(200);
    }

    private static Principal getPrincipal(String path) {
        // extracts the dn or username identity from a path
        String[] parts = path.split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid path " + path);
        }
        Principal delegatedUser;
        if ("dn".equalsIgnoreCase(parts[0])) {
            delegatedUser = new X500Principal(parts[1]);
        } else if ("userid".equalsIgnoreCase(parts[0])) {
            delegatedUser = new HttpPrincipal(parts[1]);
        } else {
            throw new IllegalArgumentException("Only dn and userid delegations supported: " + path);
        }
        return delegatedUser;
    }

    /**
     * Generates a certificate signed with subject's credentials (CADC private
     * key) and returns it.
     *
     * @param user The X500Name to generate for.
     * @param daysValid Days the certificate will be valid for
     * @return X509CertificateChain generated and signed certificate chain
     * @throws NoSuchAlgorithmException
     * @throws IllegalStateException
     * @throws CertificateException
     * @throws CertificateNotYetValidException
     * @throws CertificateExpiredException
     * @throws IOException
     */
    private X509Certificate generateCertificate(final X500Name user, PublicKey publicKey, X509CertificateChain signer, float daysValid)
            throws NoSuchAlgorithmException,
            IllegalStateException, CertificateException,
            OperatorCreationException, IOException {


        // enforce this or not?
        //        if (!canonizedDN.contains(CADC_DN))
        //        {
        //            throw new IllegalArgumentException(
        //                    "Wrong o, ou, or c fields in user DN: " + userDN);
        //        }

        // set validity
        GregorianCalendar notBeforeDate = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        notBeforeDate.add(Calendar.MINUTE, -5); // Allow for a five-minute skewed clock
        GregorianCalendar notAfterDate = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        notAfterDate.add(Calendar.HOUR, Math.round(daysValid * 24));

        //
        // create the certificate - version 3
        //
        X500Principal signerUser = signer.getChain()[0].getSubjectX500Principal();
        log.debug("Create cert for user " + user + " signed by " + signerUser);
        X509v3CertificateBuilder v3CertBldr = new X509v3CertificateBuilder(
                X500Name.getInstance(signerUser.getEncoded()),
                BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(100)),
                notBeforeDate.getTime(),
                notAfterDate.getTime(),
                user,
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));

        //
        // extensions
        //
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        v3CertBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        v3CertBldr.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(publicKey));
        v3CertBldr.addExtension(Extension.authorityKeyIdentifier, false,
                utils.createAuthorityKeyIdentifier(signer.getChain()[0].getPublicKey()));

        log.debug("Generate certificate");
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(CertUtil.DEFAULT_SIGNATURE_ALGORITHM).setProvider("BC");
        X509CertificateHolder ch = v3CertBldr.build(signerBuilder.build(signer.getPrivateKey()));

        return new JcaX509CertificateConverter().getCertificate(ch);
    }
}
