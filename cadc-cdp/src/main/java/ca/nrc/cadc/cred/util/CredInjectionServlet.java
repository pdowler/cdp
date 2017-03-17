/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2017.                            (c) 2017.
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

package ca.nrc.cadc.cred.util;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.client.CredUtil;
import ca.nrc.cadc.log.ServletLogInfo;
import org.apache.log4j.Logger;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;

/**
 * Allow an authorized user to upload a privileged certificate chain
 * that is to be stored in JNDI.  This chain is for use by clients
 * that need to perform bootstrap operations such as obtaining
 * users' delegated certificates for secondary web service calls.
 *
 * Created by majorb on 15/03/17.
 */
public class CredInjectionServlet extends HttpServlet
{
    private static final Logger log = Logger.getLogger(CredInjectionServlet.class);
    private static final String AUTHORIZED_DN = "authorized_dn";
    private static final double MAX_CERT_SIZE_BYTES = Math.pow(2, 16);  // 64K
    private String authorizedDN;

    public void init(ServletConfig config) throws ServletException
    {
        authorizedDN = config.getInitParameter(AUTHORIZED_DN);
        if (authorizedDN == null)
            throw new ExceptionInInitializerError("No authorized users configured to inject credentials.");
        authorizedDN = authorizedDN.replace("\"", "");
        authorizedDN = AuthenticationUtil.canonizeDistinguishedName(authorizedDN);
    }

    public void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException
    {
        ServletLogInfo logInfo = new ServletLogInfo(request);
        long start = System.currentTimeMillis();
        log.info(logInfo.start());
        try
        {
            Subject subject = AuthenticationUtil.getSubject(request);
            log.debug("Subject: " + subject);
            logInfo.setSubject(subject);
            if (subject == null)
            {
                // unauthorized request
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            Set<X500Principal> x500Principals = subject.getPrincipals(X500Principal.class);
            boolean isAuthorized = false;
            Iterator<X500Principal> i = x500Principals.iterator();
            String nextDN = null;
            while (i.hasNext())
            {
                nextDN = AuthenticationUtil.canonizeDistinguishedName(i.next().getName());
                if (nextDN.equals(authorizedDN))
                    isAuthorized = true;
            }

            if (!isAuthorized)
            {
                // permission denied
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                return;
            }

            X509CertificateChain chain = uploadCert(request);
            storeInJNDI(chain);
        }
        catch (Throwable t)
        {
            String message = "Unexpected error: " + t.getMessage();
            log.error(message, t);
            logInfo.setSuccess(false);
            logInfo.setMessage(message);
            if (!response.isCommitted())
            {
                try
                {
                    response.getWriter().write(message);
                }
                catch (IOException e)
                {
                    log.warn("Failed to write message to response", e);
                }
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
            else
            {
                log.warn("Response already committed.");
            }
        }
        finally
        {
            long elapsed = System.currentTimeMillis() - start;
            logInfo.setElapsedTime(elapsed);
            log.info(logInfo.end());
        }

    }

    private X509CertificateChain uploadCert(HttpServletRequest request) throws Exception
    {
        byte[] buff = new byte[1024];
        InputStream in = request.getInputStream();

        int bytesRead, totalBytesRead = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while ((bytesRead = in.read(buff, 0, 1024)) > 0)
        {
            totalBytesRead += bytesRead;
            if (totalBytesRead > MAX_CERT_SIZE_BYTES)
                throw new IllegalArgumentException("Certificate chain too big.");
            out.write(buff, 0, bytesRead);
        }
        out.flush();
        log.debug("Uploaded cert: " + out.toString());

        return SSLUtil.readPemCertificateAndKey(out.toByteArray());
    }

    private void storeInJNDI(X509CertificateChain chain) throws NamingException
    {
        InitialContext ic = new InitialContext();
        try
        {
            // unbind to be safe
            ic.unbind(CredUtil.SERVOPS_JNDI_NAME);
            log.debug("Unbound previously bound certificate.");
        }
        catch (NamingException e)
        {
            // happens when nothing to unbind, expected
            log.debug("No certificate to unbind");
        }
        ic.bind(CredUtil.SERVOPS_JNDI_NAME, chain);
        log.debug("Stored certificate in JNDI.");
    }
}
