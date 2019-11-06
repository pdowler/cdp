/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2011.                            (c) 2011.
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

package ca.nrc.cadc.cred.server;

import java.io.IOException;
import java.security.AccessControlException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.astrogrid.security.delegation.DelegationServlet;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.log.ServletLogInfo;
import ca.nrc.cadc.log.WebServiceLogInfo;

/**
 * This servlet is used in inject AccessControl information
 */
public class CadcDelegationServlet extends DelegationServlet
{
    private static final long serialVersionUID = 2740612605831268729L;
    private static Logger LOGGER = Logger.getLogger(CadcDelegationServlet.class);
    public static final String SU_DNS = "suDNs";
    private Set<X500Principal> suDNs = new HashSet<X500Principal>();

    /**
     * Read the configuration.
     */
    public void init(final ServletConfig config) 
        throws ServletException
    {
        super.init(config);
        String suDNStr = config.getInitParameter(SU_DNS);
        if (suDNStr != null)
        {
            String[] dns = suDNStr.split("\n");
            for (String dn : dns)
            {
                String sp = dn.replaceAll("\"", "").trim();
                X500Principal su = new X500Principal(sp);
                suDNs.add(su);
                LOGGER.info("SU: " + su.getName());
            }
        }
    }

    /**
     * Determines the caller subject before passing the request to the
     * DelegationServlet.
     * 
     * @param request
     *            servlet request
     * @param response
     *            servlet response
     */
    @Override
    protected void service(final HttpServletRequest request,
            final HttpServletResponse response) throws IOException
    {
        WebServiceLogInfo logInfo = new ServletLogInfo(request);
        LOGGER.info(logInfo.start());
        long start = System.currentTimeMillis();
        try
        {
            final Subject currentSubject = createSubject(request);
            logInfo.setSubject(currentSubject);
            
            Subject.doAs(currentSubject,
                    new PrivilegedExceptionAction<Object>()
                    {
                        public Object run() throws IOException
                        {
                            handleService(request, response);
                            return null; // nothing to return
                        }
                    });
        }
        catch (Throwable t)
        {
            LOGGER.debug(t);
            if (t instanceof PrivilegedActionException)
            {
                t = ((PrivilegedActionException)t).getCause();
                LOGGER.debug(t);
            }
            
            logInfo.setMessage(t.getMessage());
            logInfo.setSuccess(false);
            
            if (t instanceof AccessControlException)
            {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().println("Unauthorized");
            }
            else if (t instanceof IllegalArgumentException)
            {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().println("Bad Request: " + t.getMessage());
            }
            else
            {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().println("Internal Error: " + t.getMessage());
            }
        }
        finally
        {
            logInfo.setElapsedTime(System.currentTimeMillis() - start);
            LOGGER.info(logInfo.end());
        }
    }

    private void handleService(HttpServletRequest request,
            HttpServletResponse response) throws IOException
    {
        super.service(request, response);
    }

    /**
     * Create a subject, and add all of the X509 Principals into it.
     * 
     * @param request
     *            The Request to create from.
     * @return An instance of a Subject.
     */
    @SuppressWarnings("unchecked")
    private Subject createSubject(final HttpServletRequest request)
    {
        X509Certificate[] ca = (X509Certificate[]) request
                .getAttribute("javax.servlet.request.X509Certificate");
        Collection<X509Certificate> certs = null;
        if (ca != null && ca.length > 0)
            certs = Arrays.asList(ca);
        // only ssl connections accepted (no remote user)

        Subject callerSubject = AuthenticationUtil.getSubject(request);
        Subject ret = callerSubject;
        
        // check whether user is superuser executing something on users
        // behalf
        String userDN = request.getParameter("DN");
        if (userDN != null)
        {
            Set<X500Principal> authPS = callerSubject.getPrincipals(X500Principal.class);
            boolean isSU = false;
            for (X500Principal caller : authPS)
            {
                for (X500Principal suDN : suDNs)
                {
                    if (AuthenticationUtil.equals(caller, suDN))
                    {
                        // super user doing something on users behalf
                        // build and return a different subject
                        isSU = true;
                    }
                    
                }
            }
            if (isSU)
            {
                X500Principal delegatedPrinc = new X500Principal(userDN);
                ret = new Subject();
                ret.getPrincipals().add(delegatedPrinc);
                LOGGER.debug("Superuser ... access on behalf of user " + userDN);
            }
            else
            {
                throw new AccessControlException("create certficate for " + userDN);
            }
        }
        
        
        return ret;
    }
}
