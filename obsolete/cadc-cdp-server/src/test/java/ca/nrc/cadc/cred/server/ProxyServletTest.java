/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2011.                            (c) 2011.
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 *
 * @author adriand
 * 
 * @version $Revision: $
 * 
 * 
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.cred.server;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Map;

import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;

import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.log.WebServiceLogInfo;
import ca.nrc.cadc.util.Log4jInit;
import org.apache.log4j.Level;
import org.bouncycastle.openssl.PEMWriter;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.easymock.EasyMock.*;


/**
 * Mock test of the ProxyServlet
 * @author pdowler
 */
public class ProxyServletTest
{

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.cdp.server", Level.INFO);
    }
    
    @Test
    public void testInit() throws Exception
    {
        ProxyServlet testServlet = new ProxyServlet();
        ServletConfig configMock = createMock(ServletConfig.class);
        String expectedDN1 = "cn=test1,ou=hia.nrc.ca,o=grid,c=ca";
        Float expectedDaysValid1 = 30.0f;
        String expectedDN2 = "cn=test2,ou=hia.nrc.ca,o=grid,c=ca";
        Float expectedDaysValid2 = 0.5f;
        expect(configMock.getInitParameter(ProxyServlet.TRUSTED_PRINCIPALS_PARAM))
                .andReturn((expectedDN1 + '\n' + expectedDN2 + ": " + expectedDaysValid2));
        
        expect(configMock.getInitParameter(ProxyServlet.DSNAME)).andReturn("jdbc/foo");
        expect(configMock.getInitParameter(ProxyServlet.CATALOG)).andReturn("foo");
        expect(configMock.getInitParameter(ProxyServlet.SCHEMA)).andReturn("bar");
        
        replay(configMock);

        testServlet.init(configMock);

        Map<X500Principal, Float> trustedDNs = testServlet
                .getTrustedPrincipals();

        assertEquals(expectedDaysValid1, trustedDNs
                .get(new X500Principal(expectedDN1)));
        assertEquals(expectedDaysValid2, trustedDNs
                .get(new X500Principal(expectedDN2)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFailInit() throws Exception
    {
        ProxyServlet testServlet = new ProxyServlet();
        ServletConfig configMock = createMock(ServletConfig.class);
        String expectedDN1 = "cn=test1,ou=hia.nrc.ca,o=grid,c=ca";
        Float expectedDaysValid1 = -0.5f;
        expect(
                configMock
                        .getInitParameter(ProxyServlet.TRUSTED_PRINCIPALS_PARAM))
                .andReturn((expectedDN1 + ":" + expectedDaysValid1));

        replay(configMock);

        testServlet.init(configMock);

    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testFailInit2() throws Exception
    {
        ProxyServlet testServlet = new ProxyServlet();
        ServletConfig configMock = createMock(ServletConfig.class);
        String expectedDN1 = "cn=test1,ou=hia.nrc.ca,o=grid,c=ca: WRONG FLOAT";
        expect(configMock.getInitParameter(
                ProxyServlet.TRUSTED_PRINCIPALS_PARAM)).andReturn(expectedDN1);

        replay(configMock);

        testServlet.init(configMock);

    }

    @Test
    public void writeCertificateChain() throws Exception
    {
        final String payload = "*** MY CHAIN ***\n*** MY PRIVATE KEY ***";

        final ProxyServlet testSubject = new ProxyServlet()
        {
            /**
             * Write out the PEM information.
             *
             * @param certificateChain The certificate chain to write.
             * @param pemWriter        The PEM Writer to write out to.
             * @throws IOException
             */
            @Override
            void writePEM(final X509CertificateChain certificateChain,
                          final PEMWriter pemWriter) throws IOException
            {
                pemWriter.write(payload);
            }
        };

        final WebServiceLogInfo mockLogInfo =
                createMock(WebServiceLogInfo.class);
        final HttpServletResponse mockResponse =
                createMock(HttpServletResponse.class);
        final X509CertificateChain mockCertificateChain =
                createMock(X509CertificateChain.class);
        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        mockResponse.setStatus(200);
        expectLastCall().once();

        mockResponse.setContentType(ProxyServlet.CERTIFICATE_CONTENT_TYPE);
        expectLastCall().once();

        mockResponse.setHeader("Content-Disposition",
                               "attachment; filename=cadcproxy.pem");
        expectLastCall().once();

        expect(mockResponse.getWriter()).andReturn(printWriter).once();

        mockLogInfo.setBytes(new Integer(payload.length()).longValue());
        expectLastCall().once();

        replay(mockResponse, mockLogInfo, mockCertificateChain);

        testSubject.writeCertificateChain(mockCertificateChain, mockResponse,
                                          mockLogInfo);

        assertEquals("Wrong output.", payload, writer.toString());

        verify(mockResponse, mockLogInfo, mockCertificateChain);
    }
}
