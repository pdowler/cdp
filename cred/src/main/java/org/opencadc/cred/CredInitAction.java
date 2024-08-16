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

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.IdentityManager;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.rest.InitAction;
import ca.nrc.cadc.util.InvalidConfigException;
import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.PropertiesReader;
import ca.nrc.cadc.vosi.avail.CheckCertificate;
import ca.nrc.cadc.vosi.avail.CheckException;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;

/**
 * Validate config and put CredConfig object into JNDI and init the database
 * (create or update tables).
 * 
 * @author pdowler
 */
public class CredInitAction extends InitAction {
    private static final Logger log = Logger.getLogger(CredInitAction.class);

    private static final String CONFIG_FILE = "cred.properties";
    private static final String MAX_VALID_PROP = "org.opencadc.cred.maxDaysValid";
    private static final String SUPERUSER = "org.opencadc.cred.superUser";
    public static final File SIGN_CERT_FILE = new File(System.getProperty("user.home") + "/.ssl/signcert.pem");

    private String jndiKey;

    public CredInitAction() {
    }

    @Override
    public void doInit() {
        initBasicAuthIdentityManager();
        this.jndiKey = getJndiKey(super.appName);
        initConfig();
    }

    @Override
    public void doShutdown() {
        try {
            Context initialContext = new InitialContext();
            initialContext.unbind(jndiKey);
        } catch (NamingException ex) {
            log.debug("BUG: unable to unbind CredConfig with key " + jndiKey, ex);
        }
    }

    private static String getJndiKey(String appName) {
        return appName + "." + CredConfig.class.getSimpleName();
    }

    public static CredConfig getConfig(String app) {
        String jndiConfigKey = getJndiKey(app);
        try {
            Context ctx = new InitialContext();
            return ((CredConfig) ctx.lookup(jndiConfigKey));
        } catch (Exception oops) {
            throw new RuntimeException("BUG: cred config not found. Service init failure?", oops);
        }
    }

    private void initBasicAuthIdentityManager() {
        String cname = System.getProperty(IdentityManager.class.getName());
        if (cname != null) {
            try {
                Class c = Class.forName(cname);
                IdentityManager o = (IdentityManager) c.getConstructor().newInstance();
                // replace it with the BasicAuthIdentityManager
                System.setProperty(IdentityManager.class.getName(), BasicAuthIdentityManager.class.getName());
                System.setProperty(BasicAuthIdentityManager.class.getName(), cname);
                log.debug("BasicAuthIndentityManager configured");
            } catch (ClassNotFoundException
                     | IllegalAccessException | IllegalArgumentException | InstantiationException
                     | NoSuchMethodException | SecurityException | InvocationTargetException ex) {
                throw new InvalidConfigException("failed to load configured IdentityManager: " + cname, ex);
            }
        }

    }
    
    private void initConfig() {
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
                credConfig.maxDaysValid = maxDaysValid;
            } catch (NumberFormatException ex) {
                throw new RuntimeException("CONFIG: invalid " + MAX_VALID_PROP + " = " + smax, ex);
            }
        }

        log.debug(MAX_VALID_PROP + " value: " + credConfig.maxDaysValid);

        if (SIGN_CERT_FILE.exists() && SIGN_CERT_FILE.canRead()) {
            CheckCertificate checkCert = new CheckCertificate(SIGN_CERT_FILE);
            try {
                checkCert.check();
                SSLUtil.readPemCertificateAndKey(SIGN_CERT_FILE);
                credConfig.signingCert = SIGN_CERT_FILE.getAbsolutePath();
            } catch (CheckException | CertificateException | InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException("Invalid signing cert: " + SIGN_CERT_FILE.getPath(), e);
            }
        } else {
            throw new RuntimeException("Signing cert not found or unreadable at: " + SIGN_CERT_FILE.getAbsolutePath());
        }

        log.debug("Signing cert: " + SIGN_CERT_FILE.getAbsolutePath());

        for (String superuser : mvp.getProperty(SUPERUSER)) {
            credConfig.superUsers.add(new X500Principal(AuthenticationUtil.canonizeDistinguishedName(superuser)));
        }

        log.debug("Added " + credConfig.superUsers.size() + " to superusers");

        try {
            Context initialContext = new InitialContext();
            initialContext.bind(jndiKey, credConfig);
        } catch (NamingException ex) {
            throw new IllegalStateException("BUG: unable to bind CredConfig to key " + jndiKey, ex);
        }
    }
}
