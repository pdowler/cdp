/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2022.                            (c) 2022.
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

package org.opencadc.cred;

import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.client.CredClient;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;
import java.io.File;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import javax.security.auth.Subject;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author pdowler
 */
public class ProxyTest 
{
    private static final Logger log = Logger.getLogger(ProxyTest.class);

    private static final URI RESOURCE_IDENTIFIER = URI.create("ivo://cadc.nrc.ca/cred");
    
    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.cred", Level.INFO);
    }
    
    public ProxyTest() { }
    
    @Test
    public void testGetProxy()
    {
        try
        {
            // TODO: need a real external certificate where 
            // -- the DN *does not* to a registered user (eg augments)
            // -- the certificate is *not* managed by cadc-cert-gen
            File cf = FileUtil.getFileFromResource("servops.pem", DelegationTest.class);
            Subject caller = SSLUtil.createSubject(cf);
            log.info("subject: " + caller);
            
            File cf2 = FileUtil.getFileFromResource("x509_CADCRegtest1.pem", DelegationTest.class);
            final Subject target = SSLUtil.createSubject(cf2);
            Assert.assertEquals(2, target.getPublicCredentials().size()); // X509CertificateChain + AuthMethod
            Iterator iter = target.getPublicCredentials().iterator();
            while ( iter.hasNext() )
            {
                Object o = iter.next();
                if (o instanceof X509CertificateChain)
                    iter.remove();
            }
            Assert.assertEquals(1, target.getPublicCredentials().size()); // AuthMethod
            log.info("target: " + target);
            
            final CredClient cred = new CredClient(RESOURCE_IDENTIFIER);
            X509CertificateChain chain = Subject.doAs(caller, new PrivilegedExceptionAction<X509CertificateChain>()
            {
                @Override
                public X509CertificateChain run() throws Exception
                {
                    X509CertificateChain chain = cred.getProxyCertificate(target, 0.1);
                    return chain;
                }
            });
            Assert.assertNotNull("chain", chain);
            for (X509Certificate c : chain.getChain())
            {
                c.checkValidity();
            }
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }
}
