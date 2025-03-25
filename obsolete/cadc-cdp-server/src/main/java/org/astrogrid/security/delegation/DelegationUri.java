package org.astrogrid.security.delegation;

/**
 * A minimal parser for the path of a URI in the delgations service.
 * The constructor must be fed the "path info" string from the HTTP request:
 * i.e. the part of the path following the servlet path (refer to the 
 * documentation for javax.http.HttpServletRequest for details).
 *
 * @author Guy Rixon
 */
public class DelegationUri {
  private String[] pathElements;
  public final static int UNKNOWN     = 0;
  public final static int LIST        = 1;
  public final static int IDENTITY    = 2;
  public final static int CSR         = 3;
  public final static int CERTIFICATE = 4;
  
  /**
   * Constructs a DelegationUri.
   */
  public DelegationUri(String path) {
    if (path == null) {
      path = "/";
    }
    this.pathElements = path.split("/");
  }
  
  public boolean isValid() {
    return (getResourceCode() != UNKNOWN);
  }
  
  public String getUser() {
    return (pathElements.length > 1)? pathElements[1] : null;
  
  }
  
  public int getResourceCode() {
    switch (this.pathElements.length) {
      case 0:
      case 1:
        return LIST;
      case 2:
        return IDENTITY;
      case 3:
        if (this.pathElements[2].equals("CSR")) {
          return CSR;
        }
        else if (this.pathElements[2].equals("certificate")) {
          return CERTIFICATE;
        }
        else {
          return UNKNOWN;
        }
      default:
        return UNKNOWN;
    }
  }
  
  
}
