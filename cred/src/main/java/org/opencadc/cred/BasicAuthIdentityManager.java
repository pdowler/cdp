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
import ca.nrc.cadc.auth.AuthorizationToken;
import ca.nrc.cadc.auth.AuthorizationTokenPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityManager;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.io.ByteLimitExceededException;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.net.ResourceAlreadyExistsException;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.InvalidConfigException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URL;
import java.security.AccessControlException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;

/**
 *  Implements the basic authentication validation of an Identity Manager. The rest of the functionality is delegated to the main Identity
 *  Manager that a service is configured with.
 * @author adriand
 */
public class BasicAuthIdentityManager implements IdentityManager {
    private static final Logger log = Logger.getLogger(BasicAuthIdentityManager.class);

    private final IdentityManager origIM;

    public BasicAuthIdentityManager() {
        String cname = System.getProperty(BasicAuthIdentityManager.class.getName());
        if (cname != null) {
            try {
                Class c = Class.forName(cname);
                this.origIM = (IdentityManager) c.getConstructor().newInstance();
                return;
            } catch (ClassNotFoundException
                     | IllegalAccessException | IllegalArgumentException | InstantiationException
                     | NoSuchMethodException | SecurityException | InvocationTargetException ex) {
                throw new InvalidConfigException("failed to load configured IdentityManager: " + cname, ex);
            }
        }
        throw new RuntimeException("BUG: Cannot load original identity manager");
    }

    @Override
    public Set<URI> getSecurityMethods() {
        Set<URI> ret = new TreeSet<>();
        ret.addAll(origIM.getSecurityMethods());
        ret.add(Standards.SECURITY_METHOD_HTTP_BASIC);
        return ret;
    }

    @Override
    public Subject validate(Subject subject) throws AccessControlException {
        Subject ret = origIM.validate(subject);
        Set<AuthorizationTokenPrincipal> raw = ret.getPrincipals(AuthorizationTokenPrincipal.class);
        log.debug("raw: " + raw.size());
        
        if (!raw.isEmpty()) {
            for (AuthorizationTokenPrincipal p : raw) {
                log.debug("raw header: " + p.getHeaderKey() + " " + p.getHeaderValue());

                String[] ss = p.getHeaderValue().split(" ");
                if (ss.length != 2) {
                    throw new NotAuthenticatedException(p.getHeaderKey(), NotAuthenticatedException.AuthError.INVALID_REQUEST,
                        "incomplete authorization header");
                }
                String username = null;
                String password = null;
                if (AuthenticationUtil.CHALLENGE_TYPE_BASIC.equalsIgnoreCase(ss[0])) {
                    Base64.Decoder dec = Base64.getDecoder();
                    byte[] b = dec.decode(ss[1]);
                    String creds = new String(b); // default charset
                    String[] up = creds.split(":");
                    username = up[0];
                    password = up[1];
                }
                if (username != null && password != null) {
                    LocalAuthority loc = new LocalAuthority();
                    URI resourceID = loc.getServiceURI(Standards.SECURITY_METHOD_PASSWORD.toASCIIString());
                    if (resourceID != null) {
                        RegistryClient reg = new RegistryClient();
                        URL loginURL = reg.getServiceURL(resourceID, Standards.SECURITY_METHOD_PASSWORD, AuthMethod.ANON);
                        Map<String,Object> params = new TreeMap<>();
                        params.put("username", username);
                        params.put("password", password);
                        HttpPost login = new HttpPost(loginURL, params, true);
                        try {
                            log.debug("attempting login...");
                            login.prepare();
                            final String tokenKey = "x-vo-bearer";
                            String token = login.getResponseHeader(tokenKey);

                            List<String> domains = Arrays.asList("cadc-ccda.hia-iha.nrc-cnrc.gc.ca", "ws-cadc.canfar.net");

                            AuthorizationToken at = new AuthorizationToken("bearer", token, domains);
                            ret.getPrincipals().remove(p);
                            ret.getPrincipals().add(new HttpPrincipal(username));
                            ret.getPublicCredentials().add(at);
                            // Add the corresponding ATP and call the original validate again. If configured correctly,
                            // this should decode the cookie and extract the user DN Principal without the need to augment subject
                            ret.getPrincipals().add(new AuthorizationTokenPrincipal("Authorization", "bearer " + token));
                            log.debug("Principals " + ret.getPrincipals());
                            ret = origIM.validate(ret);
                            log.debug("Added token credentials to user " + username);
                            
                        } catch (ByteLimitExceededException | ResourceAlreadyExistsException ignore) {
                            log.debug("ignore exception: " + ignore);
                        } catch (IOException | InterruptedException | ResourceNotFoundException ex) {
                            throw new RuntimeException("CONFIG: login failed", ex);
                        }
                    }
                }
            }
        }
        return ret;
    }

    @Override
    public Subject augment(Subject subject) {
        return origIM.augment(subject);
    }

    @Override
    public Subject toSubject(Object o) {
        return origIM.toSubject(o);
    }

    @Override
    public Object toOwner(Subject subject) {
        return origIM.toOwner(subject);
    }

    @Override
    public String toDisplayString(Subject subject) {
        return origIM.toDisplayString(subject);
    }
}
