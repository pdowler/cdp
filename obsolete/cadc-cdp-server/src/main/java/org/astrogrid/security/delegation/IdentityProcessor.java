package org.astrogrid.security.delegation;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;

/**
 *
 * @author Guy Rixon
 */
public class IdentityProcessor extends ResourceProcessor {
  
  private static final Logger log = Logger.getLogger(IdentityProcessor.class);
  
  /**
   * Responds to HTTP requests.
   */
  @Override
  public void service(HttpServletRequest  request,
                      DelegationUri       path,
                      HttpServletResponse response) throws IOException {
    if (request.getMethod().equals("GET")) {
      sendIdentity(path.getUser(), response);
    }
    else if (request.getMethod().equals("DELETE")) {
      deleteIdentity(path.getUser(), response);
    }
    else {
      response.setHeader("Accept", "GET, DELETE");
      response.sendError(response.SC_METHOD_NOT_ALLOWED);
    }
  }
  
  /**
   * Writes to the client the X.500 distinguished name for an identity.
   *
   * @param hashKey The hash key for the identity to be deleted.
   * @param response The HTTP response.
   */
  private void sendIdentity(String              hashKey, 
                            HttpServletResponse response) throws IOException {
    if (Delegations.getInstance().isKnown(hashKey)) {
      String name = Delegations.getInstance().getName(hashKey);
      response.setContentType("text/plain");
      PrintWriter out = response.getWriter();
      out.println(name);
      out.close();
    }
    else {
      response.sendError(response.SC_NOT_FOUND);
    }
  }
  
  /**
   * Deletes a delegated identity from the records.
   *
   * @param hashKey The hash key for the identity to be deleted.
   * @param response The HTTP response.
   */
  private void deleteIdentity(String              hashKey, 
                              HttpServletResponse response) throws IOException {
    if (Delegations.getInstance().isKnown(hashKey)) {
      String dn = Delegations.getInstance().getName(hashKey);
      Delegations.getInstance().remove(hashKey);
      response.setStatus(response.SC_NO_CONTENT);
      log.info("Delegated powers for " + dn + "(" + hashKey + ") have been removed.");
    }
    else {
      response.sendError(response.SC_NOT_FOUND);
    }
  }
  
}
