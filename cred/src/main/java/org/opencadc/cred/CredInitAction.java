/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2021.                            (c) 2021.
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

import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.rest.InitAction;
import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.PropertiesReader;
import ca.nrc.cadc.vosi.avail.CheckCertificate;
import ca.nrc.cadc.vosi.avail.CheckException;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * Validate config and put CredConfig object into JNDI and init the database
 * (create or update tables).
 * 
 * @author pdowler
 */
public class CredInitAction extends InitAction {
    private static final Logger log = Logger.getLogger(CredInitAction.class);

    private static final String CONFIG_FILE = "cred.properties";
    private static final String MAX_VALID_PROP = "org.opencadc.cred.proxy.maxDaysValid";
    private static final String DELEGATOR = "org.opencadc.cred.delegate.allowedUser";

    public static final File SIGN_CERT_FILE = new File("/config/signcert.pem");

    private String jndiConfigKey;

    public CredInitAction() {
    }

    @Override
    public void doInit() {
        initConfig();
    }

    @Override
    public void doShutdown() {
        try {
            Context initialContext = new InitialContext();
            initialContext.unbind(jndiConfigKey);
        } catch (NamingException ex) {
            log.debug("BUG: unable to unbind CredConfig with key " + jndiConfigKey, ex);
        }
    }
    
    private void initConfig() {
        jndiConfigKey = super.appName + "-config";
        CredConfig credConfig = new CredConfig();
        PropertiesReader pr = new PropertiesReader(CONFIG_FILE);
        MultiValuedProperties mvp = pr.getAllProperties();
        if (mvp == null) {
            throw new RuntimeException("CONFIG: not found: " + CONFIG_FILE);
        }

        String smax = mvp.getFirstPropertyValue(MAX_VALID_PROP);
        if (smax != null) {
            try {
                float maxDaysValid = Float.parseFloat(smax);
                if (maxDaysValid <= 0.0) {
                    throw new RuntimeException("CONFIG: invalid " + MAX_VALID_PROP + " = " + maxDaysValid + " -- must be positive");
                }
                credConfig.proxyMaxDaysValid = maxDaysValid;
            } catch (NumberFormatException ex) {
                throw new RuntimeException("CONFIG: invalid " + MAX_VALID_PROP + " = " + smax, ex);
            }
        }

        log.debug(MAX_VALID_PROP + " value: " + credConfig.proxyMaxDaysValid);

        if (SIGN_CERT_FILE.exists() && SIGN_CERT_FILE.canRead()) {
            CheckCertificate checkCert = new CheckCertificate(SIGN_CERT_FILE);
            try {
                checkCert.check();
                SSLUtil.readPemCertificateAndKey(SIGN_CERT_FILE);
                credConfig.signingCert = SIGN_CERT_FILE.getAbsolutePath();
            } catch (CheckException | CertificateException | InvalidKeySpecException | NoSuchAlgorithmException |
                     IOException e) {
                throw new RuntimeException("Invalid signing cert: " + SIGN_CERT_FILE.getPath(), e);
            }
        } else {
            throw new RuntimeException("Signing cert not found or unreadable at: " + SIGN_CERT_FILE.getAbsolutePath());
        }

        log.debug("Signing cert: " + SIGN_CERT_FILE.getAbsolutePath());

        for (String delegator : mvp.getProperty(DELEGATOR)) {
            credConfig.delegators.add(new X500Principal(delegator));
        }

        log.debug("Added " + credConfig.delegators.size() + " allowed delegators");

        try {
            Context initialContext = new InitialContext();
            initialContext.bind(jndiConfigKey, credConfig);
        } catch (NamingException ex) {
            throw new IllegalStateException("BUG: unable to bind CredConfig to key " + jndiConfigKey, ex);
        }
    }
}
