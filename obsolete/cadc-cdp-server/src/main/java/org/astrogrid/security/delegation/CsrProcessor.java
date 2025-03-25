package org.astrogrid.security.delegation;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A servlet-like device to response to HTTP requests to the CSR resource.
 * This is like a servlet in that it works from servlet requests to responses
 * but is not itself a servlet. The CSR responds to HTTP GET only.
 *
 * @author Guy Rixon
 */
public class CsrProcessor extends ResourceProcessor {
  
  /**
   * Responds to HTTP requests.
   */
  public void service(HttpServletRequest  request,
                      DelegationUri       path,
                      HttpServletResponse response) throws IOException {
    if (request.getMethod().equals("GET")) {
      sendCsr(path.getUser(), response);
    }
    else {
      response.setHeader("Accept", "GET");
      response.sendError(response.SC_METHOD_NOT_ALLOWED);
    }
  }

  /**
   * Writes to the client the Certificate Signing Request (CSR) for a given
   * identity.
   */
  private void sendCsr(String              hashKey, 
                       HttpServletResponse response) throws IOException {
    if (Delegations.getInstance().isKnown(hashKey)) {
      try {
        CertificateSigningRequest csr = 
            Delegations.getInstance().getCsr(hashKey);
        assert csr != null;
        response.setContentType("text/plain");
        csr.writePem(response.getWriter());
      } catch (Exception ex) {
        response.sendError(response.SC_INTERNAL_SERVER_ERROR,
                           "CSR production failed: " + ex);
      }
    }
    else {
      response.sendError(response.SC_NOT_FOUND);
    }
  }
  
}
