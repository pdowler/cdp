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

import ca.nrc.cadc.cred.server.CredConfig;
import ca.nrc.cadc.cred.server.InitDatabaseCDP;
import ca.nrc.cadc.db.DBUtil;
import ca.nrc.cadc.rest.InitAction;
import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.PropertiesReader;
import java.util.List;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.x500.X500Principal;
import javax.sql.DataSource;
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
    private static final String DELEGATE_PROP  = "org.opencadc.cred.delegate.allowedUser";
    private static final String PROXY_PROP     = "org.opencadc.cred.proxy.allowedUser";
    private static final String MAX_VALID_PROP = "org.opencadc.cred.proxy.maxDaysValid";
    
    private final String jndiKey = CredConfig.JDNI_KEY; // temporarily hard coded to work with lib
    private CredConfig credConfig;
    
    public CredInitAction() { 
    }

    @Override
    public void doInit() {
        initConfig();
        initDatabase();
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
    
    private void initConfig() {
        this.credConfig = new CredConfig();
        PropertiesReader pr = new PropertiesReader(CONFIG_FILE);
        MultiValuedProperties mvp = pr.getAllProperties();
        if (mvp == null) {
            throw new RuntimeException("CONFIG: not found: " + CONFIG_FILE);
        }
        
        List<String> delegate = mvp.getProperty(DELEGATE_PROP);
        if (delegate != null) {
            for (String s : delegate) {
                X500Principal p = new X500Principal(s);
                credConfig.getDelegateUsers().add(p);
            }
        }
        log.warn(DELEGATE_PROP + " found: " + credConfig.getDelegateUsers().size());
        
        List<String> proxy = mvp.getProperty(PROXY_PROP);
        if (proxy != null) {
            for (String s : proxy) {
                X500Principal p = new X500Principal(s);
                credConfig.getProxyUsers().add(p);
            }
        }
        log.warn(PROXY_PROP + " found: " + credConfig.getProxyUsers().size());
        
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
        log.warn(MAX_VALID_PROP + " value: " + credConfig.proxyMaxDaysValid);
        
        try {
            Context initialContext = new InitialContext();
            initialContext.bind(jndiKey, credConfig);
        } catch (NamingException ex) {
            throw new IllegalStateException("BUG: unablew to bind CredConfig to key " + jndiKey, ex);
        }
    }
    
    private void initDatabase() {
        try {
            DataSource ds = DBUtil.findJNDIDataSource("jdbc/cred"); // context.xml
            InitDatabaseCDP init = new InitDatabaseCDP(ds, null, "cred");
            init.doInit();
        } catch (NamingException ex) {
            throw new RuntimeException("BUG: failed to find jdbc/cred", ex);
        }
    }
}
