

package org.opencadc.cred;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Backwards compatibility support for the getCert script from the vofs
 * package.
 */
public class ProxyCertServlet extends HttpServlet
{
    private static final long serialVersionUID = 201103041330L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException
    {
        try
        {
            RequestDispatcher rd = request.getRequestDispatcher("/auth/priv");
            rd.forward(request, response);
        }
        catch(ServletException ex)
        {
            throw new RuntimeException("CONFIG: failed to forward /proxyCert to /auth/priv");
        }
    }
}
