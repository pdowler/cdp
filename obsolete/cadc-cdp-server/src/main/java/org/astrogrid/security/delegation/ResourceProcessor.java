package org.astrogrid.security.delegation;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.astrogrid.security.delegation.*;

/**
 *
 * @author Guy Rixon
 */
public class ResourceProcessor {
  
  public void service(HttpServletRequest  request,
                      DelegationUri       path,
                      HttpServletResponse response) throws IOException {
    response.sendError(response.SC_NOT_FOUND);
  }
  
}
