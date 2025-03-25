package org.astrogrid.security.delegation;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ca.nrc.cadc.auth.SSLUtil;
import org.apache.log4j.Logger;

/**
 * 
 * @author Guy Rixon
 */
public class CertificateProcessor extends ResourceProcessor
{

    private static final Logger log = Logger.getLogger(CertificateProcessor.class);

    /**
     * Responds to HTTP requests.
     */
    @Override
    public void service(HttpServletRequest request, DelegationUri path,
            HttpServletResponse response) throws IOException
    {
        if (request.getMethod().equals("GET"))
        {
            sendCertificate(path.getUser(), response);
        }
        else if (request.getMethod().equals("PUT"))
        {
            receiveCertificate(request, path.getUser(), response);
        }
        else
        {
            response.setHeader("Accept", "GET");
            response.sendError(response.SC_METHOD_NOT_ALLOWED);
        }
    }

    /**
     * Writes to the client the X.509 certificate for an identity.
     */
    private void sendCertificate(String hashKey,
            HttpServletResponse response) throws IOException
    {
        if (Delegations.getInstance().hasCertificate(hashKey))
        {
            response.setContentType("text/plain");
            Delegations.getInstance().writeCertificate(hashKey,
                    response.getWriter());
        }
        else
        {
            response.sendError(response.SC_NOT_FOUND);
        }
    }

    /**
     * Receives an uploaded identity certificate. The certificate becomes
     * the content for they identity's /certificate resource.
     */
    private void receiveCertificate(HttpServletRequest request,
            String hashKey, HttpServletResponse response)
            throws IOException
    {
        if (Delegations.getInstance().isKnown(hashKey))
        {
            try
            {
                // the Certificate factory is quite fragile when it comes to
                // reading the PEM string. So we consume the stream, and 
                // extracts just the Certificates information from the 
                // stream by calling SSLUtil.getCertificates() and fed
                // it to the CertificateFactory
               
                int bytesRead = 0;
                int bytesToRead = 10000; // max size accepted for the input
                                         // stream
                byte[] input = new byte[bytesToRead];
                while (bytesRead < bytesToRead)
                {
                    int result = request.getInputStream().read(input,
                            bytesRead, bytesToRead - bytesRead);
                    if (result == -1)
                    {
                        break;
                    }
                    bytesRead += result;
                }
                
                if(bytesRead == bytesToRead)
                {
                    throw new 
                    CertificateException("Certificate to read too large (>" + 
                            bytesToRead + " bytes)");
                }

                byte[] code = SSLUtil.getCertificates(input);
                

                CertificateFactory factory = CertificateFactory
                .getInstance("X509");
                BufferedInputStream istream = new BufferedInputStream(
                        new ByteArrayInputStream(code));
                Collection certificates = 
                    factory.generateCertificates(istream);
                //certificate.checkValidity(); ???
                
                try
                {
                    X509Certificate[] certsArray = new X509Certificate[certificates.size()];
                    Delegations.getInstance().setCertificates(hashKey,
                            (X509Certificate[])certificates.toArray(certsArray));
                }
                catch (InvalidKeyException ex)
                {
                    throw new RuntimeException(ex);
                }
                log.info("Received a certificate for "
                        + ((X509Certificate) certificates.iterator()
                                .next()).getSubjectX500Principal() + " ("
                        + hashKey + ").");
            }
            catch (CertificateException ex)
            {
                System.out.println(ex);
                response.sendError(response.SC_BAD_REQUEST,
                        "Failed to parse the certificate: " + ex);
            }
        }
        else
        {
            response.sendError(response.SC_NOT_FOUND);
        }
    }

}
