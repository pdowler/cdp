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
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;
import java.io.ByteArrayOutputStream;
import java.io.File;
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
 *
 * @author adriand
 */
public class GetCertTest {
    private static final Logger log = Logger.getLogger(GetCertTest.class);

    private static final String SUPER_CERT_FILENAME = "cred-super.pem";
    
    // ugh: this gets set as a side effect of the most recent getToken() or addBasicAuth()
    private String netrcUserID;

    static {
        Log4jInit.setLevel("org.opencadc.cred", Level.DEBUG);
    }

    public GetCertTest() {
    }
    
    private String getToken(RegistryClient reg)
        throws ResourceAlreadyExistsException, IOException, ResourceNotFoundException, InterruptedException {
        URL capURL = reg.getServiceURL(Constants.RESOURCE_IDENTIFIER, Standards.VOSI_CAPABILITIES, AuthMethod.ANON);
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
        PasswordAuthentication up = netrc.getCredentials(loginURL.getHost(), true);
        if (up == null) {
            throw new RuntimeException("no credentials in .netrc file for host " + loginURL.getHost());
        }
        Map<String, Object> params = new TreeMap<>();
        params.put("username", up.getUserName());
        params.put("password", up.getPassword());
        HttpPost login = new HttpPost(loginURL, params, true);
        login.prepare();
        String cadcToken = login.getResponseHeader("x-vo-bearer");
        Assert.assertNotNull("successful login", cadcToken);

        // verify token
        head.setHeadOnly(true);
        head.setRequestProperty("authorization", "bearer " + cadcToken);
        head.prepare();
        String ident = head.getResponseHeader("x-vo-authenticated");
        log.info("authenticated as: " + ident);
        Assert.assertNotNull("successful authenticated call", ident);
        
        this.netrcUserID = up.getUserName();
        return cadcToken;
    }

    private void addBasicAuthHeader(HttpGet get) {
        log.info("loginURL: " + get.getURL());
        NetrcFile netrc = new NetrcFile();
        PasswordAuthentication up = netrc.getCredentials(get.getURL().getHost(), true);
        if (up == null) {
            throw new RuntimeException("no credentials in .netrc file for host " + get.getURL().getHost());
        }
        String valueToEncode = up.getUserName() + ":" + new String(up.getPassword());
        String headerValue = AuthenticationUtil.CHALLENGE_TYPE_BASIC + " " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
        get.setRequestProperty("Authorization", headerValue);
        log.info("username: " + up.getUserName() + " authorization: " + headerValue);
        this.netrcUserID = up.getUserName();
    }
    
    @Test
    public void testGetCertWithToken() throws Exception {
        // this uses a username/password from ~/.netrc to obtain a token and then
        // uses the token to obtain a certificate
        RegistryClient reg = new RegistryClient();
        URL baseURL = reg.getServiceURL(Constants.RESOURCE_IDENTIFIER, Standards.CRED_PROXY_10, AuthMethod.TOKEN);
        
        final String cadcToken = getToken(reg);
        
        float daysValid = 3; // 3 days cert
        URL credUrl = new URL(baseURL.toExternalForm() + "?daysValid=" + daysValid);
        log.info("get cert URL: " + credUrl);
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        HttpGet get = new HttpGet(credUrl, bos);
        get.setRequestProperty("authorization", "bearer " + cadcToken);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        byte[] certificate = bos.toByteArray();
        Assert.assertNotNull(certificate);
        log.debug("Downloaded Certificate of size: " + certificate.length);
        Assert.assertTrue(certificate.length > 0);

        X509CertificateChain chain = SSLUtil.readPemCertificateAndKey(certificate);
        Date now = new Date();
        int hour = 60 * 60 * 1000;
        Date expired = new Date(now.getTime() + (long) (daysValid * 24 + 1) * hour);  // add 1h after daysValid
        Assert.assertTrue(chain.getExpiryDate().after(now));
        Assert.assertTrue(chain.getExpiryDate().before(expired));
        verifyCert(chain, netrcUserID);

        // get cert by userid
        // this assumes the token ident in the netrc is configured as a super-user
        final String userID = "cadcregtest1";
        bos = new ByteArrayOutputStream();
        credUrl = new URL(baseURL.toExternalForm() + "/userid/" + userID + "?daysValid=" + daysValid);
        log.info("get cert URL: " + credUrl);
        get = new HttpGet(credUrl, bos);
        get.setRequestProperty("authorization", "bearer " + cadcToken);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        certificate = bos.toByteArray();
        chain = SSLUtil.readPemCertificateAndKey(certificate);
        log.debug("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);

        // get a cert for same user using their DN
        // same assumption as above
        final String userDN = "C=ca,O=hia,OU=cadc,CN=cadcregtest1_b5d";
        bos = new ByteArrayOutputStream();
        credUrl = new URL(baseURL.toExternalForm() + "/dn/" + userDN + "?daysValid=" + daysValid);
        log.info("get cert URL: " + credUrl);
        get = new HttpGet(credUrl, bos);
        get.setRequestProperty("authorization", "bearer " + cadcToken);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        certificate = bos.toByteArray();
        chain = SSLUtil.readPemCertificateAndKey(certificate);
        log.debug("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);

        // get a cert for a made up DN
        final String extUserDN = "C=ca,O=someorg,CN=user";
        bos = new ByteArrayOutputStream();
        credUrl = new URL(baseURL.toExternalForm() + "/dn/" + extUserDN + "?daysValid=" + daysValid);
        log.info("get cert URL: " + credUrl);
        get = new HttpGet(credUrl, bos);
        get.setRequestProperty("authorization", "bearer " + cadcToken);
        get.run();
        Assert.assertEquals(200, get.getResponseCode());
        certificate = bos.toByteArray();
        chain = SSLUtil.readPemCertificateAndKey(certificate);
        Assert.assertEquals(extUserDN, chain.getChain()[0].getSubjectX500Principal().getName());
        // it will not verify as the user is made up
    }

    @Test
    public void testGetCertWithUserPassword() throws Exception {
        // get a cert with user/password
        RegistryClient reg = new RegistryClient();
        URL credUrl = reg.getServiceURL(Constants.RESOURCE_IDENTIFIER, Standards.CRED_PROXY_10, AuthMethod.TOKEN);

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
        verifyCert(chain, netrcUserID);

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
        URL baseURL = reg.getServiceURL(Constants.RESOURCE_IDENTIFIER, Standards.CRED_PROXY_10, AuthMethod.CERT);

        File  sf = FileUtil.getFileFromResource(SUPER_CERT_FILENAME, GetCertTest.class);
        Subject superUser = SSLUtil.createSubject(sf);
        
        // get cert by userid
        String userID = "cadcregtest1";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        URL credURL = new URL(baseURL + "/userid/" + userID);
        log.info("get: " + credURL);
        HttpGet get = new HttpGet(credURL, bos);
        Subject.doAs(superUser, new RunnableAction(get));
        Assert.assertEquals(200, get.getResponseCode());
        X509CertificateChain chain = SSLUtil.readPemCertificateAndKey(bos.toByteArray());
        log.info("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);

        // get a cert for a user using their DN
        String userDN = "C=ca,O=hia,OU=cadc,CN=cadcregtest1_b5d";
        bos = new ByteArrayOutputStream();
        credURL = new URL(baseURL + "/dn/" + userDN);
        log.info("get: " + credURL);
        get = new HttpGet(credURL, bos);
        Subject.doAs(superUser, new RunnableAction(get));
        Assert.assertEquals(200, get.getResponseCode());
        chain = SSLUtil.readPemCertificateAndKey(bos.toByteArray());
        log.info("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);
    }

    @Test
    public void testGetCertFail() throws Exception {

        RegistryClient reg = new RegistryClient();
        URL credUrl = reg.getServiceURL(Constants.RESOURCE_IDENTIFIER, Standards.CRED_PROXY_10, AuthMethod.TOKEN);

        final String cadcToken = getToken(reg);
        
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
        URL credUrl = reg.getServiceURL(Constants.RESOURCE_IDENTIFIER, Standards.CRED_PROXY_10, AuthMethod.TOKEN);

        File  sf = FileUtil.getFileFromResource(SUPER_CERT_FILENAME, GetCertTest.class);
        Subject superUser = SSLUtil.createSubject(sf);
        
        // try to renew superuser
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        HttpGet get = new HttpGet(credUrl, bos);
        Subject.doAs(superUser, new RunnableAction(get));
        log.info("super self renew: " + get.getResponseCode() + " " + get.getThrowable());
        Assert.assertEquals(403, get.getResponseCode());

        // get a user cert
        String userID = "cadcregtest1";
        bos = new ByteArrayOutputStream();
        get = new HttpGet(new URL(credUrl + "/userid/" + userID), bos);
        Subject.doAs(superUser, new RunnableAction(get));
        Assert.assertEquals(200, get.getResponseCode());
        log.info("super get user: " + get.getResponseCode() + " " + get.getThrowable());
        byte[] certificate = bos.toByteArray();
        X509CertificateChain chain = SSLUtil.readPemCertificateAndKey(certificate);
        log.debug("Retrieved cert for " + chain.getChain()[0].getSubjectX500Principal());
        verifyCert(chain, userID);

        // try to renew user cert
        Subject regUser = AuthenticationUtil.getSubject(chain);
        bos = new ByteArrayOutputStream();
        get = new HttpGet(credUrl, bos);
        Subject.doAs(regUser, new RunnableAction(get));
        log.info("user self renew: " + get.getResponseCode() + " " + get.getThrowable());
        Assert.assertEquals(403, get.getResponseCode());
    }

    private void verifyCert(X509CertificateChain cert, String userID) throws PrivilegedActionException {
        // use the cert to access capabilities and check the authenticated user header
        RegistryClient reg = new RegistryClient();
        URL capURL = reg.getServiceURL(Constants.RESOURCE_IDENTIFIER, Standards.VOSI_CAPABILITIES, AuthMethod.ANON);

        Subject userSubject = AuthenticationUtil.getSubject(cert);
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
