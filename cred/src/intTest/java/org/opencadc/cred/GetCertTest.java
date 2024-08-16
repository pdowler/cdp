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
*  $Revision: 4 $
*
************************************************************************
*/

package org.opencadc.cred;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.RunnableAction;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.net.AuthChallenge;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.net.NetrcFile;
import ca.nrc.cadc.net.ResourceAlreadyExistsException;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.Log4jInit;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.security.auth.Subject;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

/**
 * Class to test a cred service. The test requires that an entry in the ~/.netrc file corresponding to a super-user identity
 * to be used in the test for the CADC login URL. (user must be configured as a superuser in the test service)
 * @author adriand
 */
public class GetCertTest
{
    private static final Logger log = Logger.getLogger(GetCertTest.class);
    
    private static final URI RESOURCE_IDENTIFIER = URI.create("ivo://cadc.nrc.ca/cred");

    private final PasswordAuthentication up;
    private final String cadcToken;
    
    static
    {
        Log4jInit.setLevel("org.opencadc.cred", Level.DEBUG);
    }
    
    public GetCertTest() throws ResourceAlreadyExistsException, IOException, ResourceNotFoundException, InterruptedException {
        RegistryClient reg = new RegistryClient();
        URL capURL = reg.getServiceURL(RESOURCE_IDENTIFIER, Standards.VOSI_CAPABILITIES, AuthMethod.ANON);
        HttpGet head = new HttpGet(capURL, false);
        head.setHeadOnly(true);
        head.prepare();

        URL tmpLoginURL = null;
        List<String> authHeaders = head.getResponseHeaderValues("www-authenticate");
        List<String> modifiable = new ArrayList<>(authHeaders);
        modifiable.remove("ivoa_x509");
        authHeaders = modifiable;

        if (authHeaders.isEmpty()) {
            throw new RuntimeException("Authorization info expected");
        }

        for (String s : authHeaders) {
            log.info(s);
            AuthChallenge c = new AuthChallenge(s);
            log.info(c);
            if ("ivoa_bearer".equals(c.getName()) && Standards.SECURITY_METHOD_PASSWORD.toASCIIString().equals(c.getParamValue("standard_id"))) {
                tmpLoginURL = new URL(c.getParamValue("access_url"));
                break;
            }
        }

        if (tmpLoginURL == null) {
            throw new RuntimeException("no www-authenticate ivoa_bearer " + Standards.SECURITY_METHOD_PASSWORD.toASCIIString() + " challenge");
        }
        URL loginURL = tmpLoginURL;

        log.info("loginURL: " + loginURL);
        NetrcFile netrc = new NetrcFile();
        up = netrc.getCredentials(loginURL.getHost(), true);
        if (up == null) {
            throw new RuntimeException("no credentials in .netrc file for host " + loginURL.getHost());
        }
        Map<String,Object> params = new TreeMap<>();
        params.put("username", up.getUserName());
        params.put("password", up.getPassword());
        HttpPost login = new HttpPost(loginURL, params, true);
        login.prepare();
        cadcToken = login.getResponseHeader("x-vo-bearer");
        Assert.assertNotNull("successful login", cadcToken);

        head.setHeadOnly(true);
        head.setRequestProperty("authorization", "bearer " + cadcToken);
        head.prepare();
        String ident = head.getResponseHeader("x-vo-authenticated");
        log.info("authenticated as: " + ident);
        Assert.assertNotNull("successful authenticated call", ident);
    }
    
    @Test
    public void testGetCertWithToken() throws Exception {
        // try various methods of exchanging user credentials for tokens that can be used back to authenticate
        RegistryClient reg = new RegistryClient();
        URL credUrl = reg.getServiceURL(RESOURCE_IDENTIFIER, Standards.CRED_PROXY_10, AuthMethod.TOKEN);

        log.debug("get cert, URL=" + credUrl);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        float daysValid = 3; // 3 days cert
        HttpGet get = new HttpGet(new URL(credUrl.toString() + "?daysValid=" + daysValid), bos);
        get.setRequestProperty("authorization", "bearer " + cadcToken);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        byte[] certificate = bos.toByteArray();
        Assert.assertNotNull(certificate);
        log.debug("Downloaded Certificate of size: " + certificate.length);
        Assert.assertTrue(certificate.length > 0);

        X509CertificateChain chain = SSLUtil.readPemCertificateAndKey(certificate);
        Date now = new Date();
        int hour = 60*60*1000;
        Date expired = new Date(now.getTime() + (long)(daysValid*24+1)*hour);  // add 1h after daysValid
        Assert.assertTrue(chain.getExpiryDate().after(now));
        Assert.assertTrue(chain.getExpiryDate().before(expired));
        verifyCert(chain);

        // get cert by userid
        String userID = "cadcregtest1";
        bos = new ByteArrayOutputStream();
        get = new HttpGet(new URL(credUrl + "/userid/" + userID), bos);
        get.setRequestProperty("authorization", "bearer " + cadcToken);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        certificate = bos.toByteArray();
        chain = SSLUtil.readPemCertificateAndKey(certificate);
        log.debug("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);

        // get a cert for same user using their DN
        String userDN = "C=ca,O=hia,OU=cadc,CN=cadcregtest1_b5d";
        bos = new ByteArrayOutputStream();
        get = new HttpGet(new URL(credUrl + "/dn/" + userDN), bos);
        get.setRequestProperty("authorization", "bearer " + cadcToken);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        certificate = bos.toByteArray();
        chain = SSLUtil.readPemCertificateAndKey(certificate);
        log.debug("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);

        // get a cert for a made up DN
        userDN = "C=ca,O=someorg,CN=user";
        bos = new ByteArrayOutputStream();
        get = new HttpGet(new URL(credUrl + "/dn/" + userDN), bos);
        get.setRequestProperty("authorization", "bearer " + cadcToken);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        certificate = bos.toByteArray();
        chain = SSLUtil.readPemCertificateAndKey(certificate);
        Assert.assertEquals(userDN, chain.getChain()[0].getSubjectX500Principal().getName());
        // it will not verify as the user is made up
    }

    @Test
    public void testGetCertWithUserPassword() throws Exception {
        // get a cert with user/password
        RegistryClient reg = new RegistryClient();
        URL credUrl = reg.getServiceURL(RESOURCE_IDENTIFIER, Standards.CRED_PROXY_10, AuthMethod.TOKEN);

        float daysValid = 3; // 3 days cert
        URL credDaysValidURL = new URL(credUrl.toString() + "?daysValid=" + daysValid);
        log.debug("get cert, URL=" + credDaysValidURL);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        HttpGet get = new HttpGet(credDaysValidURL, bos);
        addBasicAuthHeader(get);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        byte[] certificate = bos.toByteArray();
        Assert.assertNotNull(certificate);
        log.debug("Downloaded Certificate of size: " + certificate.length);
        Assert.assertTrue(certificate.length > 0);

        X509CertificateChain chain = SSLUtil.readPemCertificateAndKey(certificate);
        verifyCert(chain);

        // get cert by userid
        String userID = "cadcregtest1";
        bos = new ByteArrayOutputStream();
        get = new HttpGet(new URL(credUrl + "/userid/" + userID), bos);
        addBasicAuthHeader(get);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        certificate = bos.toByteArray();
        chain = SSLUtil.readPemCertificateAndKey(certificate);
        log.debug("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);

        // get a cert for same user using their DN
        String userDN = "C=ca,O=hia,OU=cadc,CN=cadcregtest1_b5d";
        bos = new ByteArrayOutputStream();
        get = new HttpGet(new URL(credUrl + "/dn/" + userDN), bos);
        addBasicAuthHeader(get);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        certificate = bos.toByteArray();
        chain = SSLUtil.readPemCertificateAndKey(certificate);
        log.debug("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);
    }

    @Test
    public void testGetCertWithSuperuserCert() throws Exception {
        // try various methods of exchanging user credentials for tokens that can be
        RegistryClient reg = new RegistryClient();
        URL credUrl = reg.getServiceURL(RESOURCE_IDENTIFIER, Standards.CRED_PROXY_10, AuthMethod.TOKEN);

        float daysValid = 3; // 3 days cert
        URL credDaysValidURL = new URL(credUrl.toString() + "?daysValid=" + daysValid);
        log.debug("get cert, URL=" + credDaysValidURL);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        HttpGet get = new HttpGet(credDaysValidURL, bos);
        addBasicAuthHeader(get);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        byte[] certificate = bos.toByteArray();
        Assert.assertNotNull(certificate);
        log.debug("Downloaded Certificate of size: " + certificate.length);
        Assert.assertTrue(certificate.length > 0);

        X509CertificateChain chain = SSLUtil.readPemCertificateAndKey(certificate);
        verifyCert(chain);

        Subject superUser = AuthenticationUtil.getSubject(chain);
        // get cert by userid
        String userID = "cadcregtest1";
        bos = new ByteArrayOutputStream();
        get = new HttpGet(new URL(credUrl + "/userid/" + userID), bos);
        Subject.doAs(superUser, new RunnableAction(get));
        Assert.assertEquals(200, get.getResponseCode());
        certificate = bos.toByteArray();
        chain = SSLUtil.readPemCertificateAndKey(certificate);
        log.debug("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);

        // get a cert for same user using their DN
        String userDN = "C=ca,O=hia,OU=cadc,CN=cadcregtest1_b5d";
        bos = new ByteArrayOutputStream();
        get = new HttpGet(new URL(credUrl + "/dn/" + userDN), bos);
        addBasicAuthHeader(get);
        Subject.doAs(superUser, new RunnableAction(get));
        Assert.assertEquals(200, get.getResponseCode());
        certificate = bos.toByteArray();
        chain = SSLUtil.readPemCertificateAndKey(certificate);
        log.debug("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);
    }

    @Test
    public void testGetCertFail() throws Exception {

        RegistryClient reg = new RegistryClient();
        URL credUrl = reg.getServiceURL(RESOURCE_IDENTIFIER, Standards.CRED_PROXY_10, AuthMethod.TOKEN);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // very large expiration date
        float daysValid = 300; // 300 days cert
        URL daysValidURL = new URL(credUrl.toString() + "?daysValid=" + daysValid);
        log.debug("get cert, URL=" + daysValidURL);
        HttpGet get = new HttpGet(daysValidURL, bos);
        get.setRequestProperty("authorization", "bearer " + cadcToken);
        get.run();
        Assert.assertEquals(400, get.getResponseCode()); // illegalargument
        log.debug("generate, response code: " + get.getResponseCode());
     }

     @Test
     public void testRenewWithCertFail() throws Exception {
        // test neither users or superuser can renew their certs using cert authentication
         // try various methods of exchanging user credentials for tokens that can be
         RegistryClient reg = new RegistryClient();
         URL credUrl = reg.getServiceURL(RESOURCE_IDENTIFIER, Standards.CRED_PROXY_10, AuthMethod.TOKEN);

         float daysValid = 3; // 3 days cert
         URL credDaysValidURL = new URL(credUrl.toString() + "?daysValid=" + daysValid);
         log.debug("get cert, URL=" + credDaysValidURL);
         ByteArrayOutputStream bos = new ByteArrayOutputStream();
         HttpGet get = new HttpGet(credDaysValidURL, bos);
         addBasicAuthHeader(get);
         get.run();
         Assert.assertEquals(200, get.getResponseCode());
         log.debug("generate, response code: " + get.getResponseCode());
         byte[] certificate = bos.toByteArray();
         Assert.assertNotNull(certificate);
         log.debug("Downloaded Certificate of size: " + certificate.length);
         Assert.assertTrue(certificate.length > 0);

         X509CertificateChain chain = SSLUtil.readPemCertificateAndKey(certificate);
         verifyCert(chain);

         // try to renew superuser
         Subject superUser = AuthenticationUtil.getSubject(chain);
         bos = new ByteArrayOutputStream();
         get = new HttpGet(credUrl, bos);
         Subject.doAs(superUser, new RunnableAction(get));
         Assert.assertEquals(403, get.getResponseCode());

         // get a user cert
         String userID = "cadcregtest1";
         bos = new ByteArrayOutputStream();
         get = new HttpGet(new URL(credUrl + "/userid/" + userID), bos);
         Subject.doAs(superUser, new RunnableAction(get));
         Assert.assertEquals(200, get.getResponseCode());
         certificate = bos.toByteArray();
         chain = SSLUtil.readPemCertificateAndKey(certificate);
         log.debug("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
         verifyCert(chain, userID);

         // try to renew user cert
         Subject regUser = AuthenticationUtil.getSubject(chain);
         bos = new ByteArrayOutputStream();
         get = new HttpGet(credUrl, bos);
         Subject.doAs(regUser, new RunnableAction(get));
         Assert.assertEquals(403, get.getResponseCode());
     }

    private void addBasicAuthHeader(HttpGet get) {
        String valueToEncode = up.getUserName() + ":" + new String(up.getPassword());
        String headerValue = AuthenticationUtil.CHALLENGE_TYPE_BASIC + " " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
        get.setRequestProperty("Authorization", headerValue);
    }

    private void verifyCert(X509CertificateChain cert) throws PrivilegedActionException {
        verifyCert(cert, up.getUserName());
    }

    private void verifyCert(X509CertificateChain cert, String userID) throws PrivilegedActionException {
        // use the cert to access capabilities and check the authenticated user header
        RegistryClient reg = new RegistryClient();
        URL capURL = reg.getServiceURL(RESOURCE_IDENTIFIER, Standards.VOSI_CAPABILITIES, AuthMethod.ANON);

        Subject userSubject =  AuthenticationUtil.getSubject(cert);
        boolean ok = Subject.doAs(userSubject, (PrivilegedExceptionAction<Boolean>) () -> {
            HttpGet head = new HttpGet(capURL, false);
            head.setHeadOnly(true);
            head.prepare();

            List<String> authHeaders = head.getResponseHeaderValues("x-vo-authenticated");
            Assert.assertEquals(1, authHeaders.size());
            Assert.assertEquals(userID, authHeaders.get(0));
            return Boolean.TRUE;
        });
        Assert.assertTrue("authenticated with cert", ok);
    }
}
