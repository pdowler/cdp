package org.astrogrid.security.delegation;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;


/**
 * A servlet-like device to response to HTTP requests to the delegation-list
 * resource. This is like a servlet in that it works from servlet requests to 
 * responses but is not itself a servlet. The CSR responds to HTTP GET and POST.
 *
 * @author Guy Rixon
 */
public class DelegationListProcessor extends ResourceProcessor {
  
  private static final Logger log = Logger.getLogger(DelegationListProcessor.class);
  
  /**
   * Responds to HTTP GET and POST requests.
   * Other HTTP requests are rejected.
   */
  @Override
  public void service(HttpServletRequest  request,
                      DelegationUri       path,
                      HttpServletResponse response) throws IOException {
    if (request.getMethod().equals("GET")) {
      sendDelegationList(response);
    }
    else if (request.getMethod().equals("POST")) {
      createIdentity(request, response);
    }
    else {
      response.setHeader("Accept", "GET, POST");
      response.sendError(response.SC_METHOD_NOT_ALLOWED);
    }
  }
  
  /**
   * Writes to the client a listing of the current known identities.
   */
  private void sendDelegationList(HttpServletResponse response) throws IOException {
    response.setContentType("text/plain");
    PrintWriter out = response.getWriter();
    Object[] principals = Delegations.getInstance().getPrincipals();
    for (int i = 0; i < principals.length; i++) {
      out.println(principals[i]);
    }
    out.close();
  }
  
  /**
   * Creates a new identity. Creates the identity resource and its CSR and
   * certificate children. Also creates the key-pair for the identity. Does
   * not create the identity certificate: this is loaded later by the client.
   */
  private void createIdentity(HttpServletRequest  request, 
                              HttpServletResponse response) throws IOException {
    
    String hashKey = null;
    
    try {
      
      if (request.isSecure()) {
        hashKey = createSecureIdentity(request);
        log.info("Delegation is begun for " +
             Delegations.getInstance().getName(hashKey) +
             " (" + hashKey + "; authenticated).");
      }
      else {
        hashKey = createInsecureIdentity(request);
        log.info("Delegation is begun for " +
             Delegations.getInstance().getName(hashKey) +
             " (" + hashKey + "; unauthenticated).");
      }
    }
    catch (AccessControlException ex) {
      log.info("Delegation failed: " + ex.getMessage());
      response.sendError(response.SC_BAD_REQUEST, ex.getMessage());
      return;
    }
    catch (GeneralSecurityException ex) {
      log.info("Delegation failed: " + ex.getMessage());
      response.sendError(response.SC_INTERNAL_SERVER_ERROR, ex.getMessage());
      return;
    } 
       
    StringBuffer createdUri = request.getRequestURL();
    createdUri.append('/');
    createdUri.append(hashKey);
    response.addHeader("Location", response.encodeRedirectURL(createdUri.toString()));
    response.setStatus(response.SC_CREATED);
  }
  
  /**
   * Creates a new identity from the principal authenticated by HTTPS.
   */
  private String createSecureIdentity(HttpServletRequest request) throws IOException,
                                                                         GeneralSecurityException {
    AccessControlContext acc = AccessController.getContext();
    Subject subject = Subject.getSubject(acc);
    Set<X500Principal> principals = subject.getPrincipals(X500Principal.class);
    if (principals.size() == 0) {
      throw new AccessControlException("Delegation failed because the caller is not authenticated.");
    }
    else if (principals.size() > 1)
    {
        throw new AccessControlException("Delegation failed because caller autheticated with multiple certificates");
    }
    else {
      return Delegations.getInstance().initializeIdentity(principals.iterator().next());
    }
  }
  
  /**
   * Creates a new identity from the distinguished name given as a parameter.
   */
  private String createInsecureIdentity(HttpServletRequest request) throws IOException,
                                                                           GeneralSecurityException {
    String dn = request.getParameter("DN");
    if (dn == null) {
       throw new AccessControlException("No value was given for the DN parameter.");
    }
    return Delegations.getInstance().initializeIdentity(dn);
  }
  
}
