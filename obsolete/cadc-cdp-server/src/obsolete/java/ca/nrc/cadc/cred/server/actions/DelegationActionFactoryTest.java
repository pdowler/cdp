package ca.nrc.cadc.cred.server.actions;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.net.ResourceNotFoundException;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import org.junit.Test;

import org.junit.Assert;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class DelegationActionFactoryTest
{

    static Map<X500Principal, Float> trustedPrincipals = new HashMap<X500Principal, Float>();
    
    static X500Principal TEST_X500 = new X500Principal("cn=testacct,ou=cadc,o=nrc,c=ca");
    
    static
    {
        trustedPrincipals.put(new X500Principal("cn=test,o=cadc,o=nrc,c=ca"), Float.MAX_VALUE);
    }

    private class TestDelegationActionFactory extends DelegationActionFactory
    {

        public TestDelegationActionFactory(HttpServletRequest request, Map<X500Principal, Float> trustedPrincipals)
        {
            super(request, trustedPrincipals, "DSNAME", "DATABASE", "SCHEMA");
        }
        
        @Override
        protected X500Principal getX500FromUserID(String userid) 
            throws ResourceNotFoundException
        {
            return TEST_X500;
        }
        
    }
    @Test
    public void testGetNotFoundAction() throws Exception
    {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        expect(mockRequest.getParameter("daysValid")).andReturn(null);
        expect(mockRequest.getPathInfo()).andReturn("/unknown/path/info");
        replay(mockRequest);

        DelegationActionFactory factory = new TestDelegationActionFactory(
                mockRequest, trustedPrincipals);
        DelegationAction action = factory.getDelegationAction();
        assertEquals("Wrong action type",
                DelegationActionFactory.NotFoundAction.class, action.getClass());
    }

    @Test
    public void testGetGetProxyCertByDNAction() throws Exception
    {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        expect(mockRequest.getParameter("daysValid")).andReturn(null);
        expect(mockRequest.getPathInfo()).andReturn("/dn/"+TEST_X500.getName());
        replay(mockRequest);

        DelegationActionFactory factory = new TestDelegationActionFactory(
                mockRequest, trustedPrincipals);
        DelegationAction action = factory.getDelegationAction();
        assertEquals("Wrong action type", GetProxyCertByDN.class, action.getClass());
        assertTrue("wrong target principal", AuthenticationUtil.equals(TEST_X500, action.name));
    }

    @Test
    public void testGetGetProxyCertByDNWithDaysValidAction()
            throws Exception
    {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        float daysValid = (float) 33.33;
        expect(mockRequest.getParameter("daysValid")).andReturn("33.33");
        expect(mockRequest.getPathInfo()).andReturn("/dn/"+TEST_X500.getName());
        replay(mockRequest);

        DelegationActionFactory factory = new TestDelegationActionFactory(
                mockRequest, trustedPrincipals);
        DelegationAction action = factory.getDelegationAction();
        assertEquals("Wrong action type", GetProxyCertByDN.class, action.getClass());
        assertTrue("wrong target principal", AuthenticationUtil.equals(TEST_X500, action.name));
        assertEquals(daysValid, action.daysValid, 0.000001);
    }

    @Test
    public void testGetGetProxyCertByDNWithMaxDaysValidAction()
            throws Exception
    {
        // not days specified, so default is 0 for now.
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        expect(mockRequest.getParameter("daysValid")).andReturn(null);
        expect(mockRequest.getPathInfo()).andReturn("/dn/"+TEST_X500.getName());
        replay(mockRequest);

        DelegationActionFactory factory = new TestDelegationActionFactory(
                mockRequest, trustedPrincipals);
        DelegationAction action = factory.getDelegationAction();
        assertEquals("Wrong action type", GetProxyCertByDN.class, action.getClass());
        assertTrue("wrong target principal", AuthenticationUtil.equals(TEST_X500, action.name));
        assertNull(action.daysValid);
    }

    @Test
    public void testGetGetProxyCertByUseridAction() throws Exception
    {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        expect(mockRequest.getParameter("daysValid")).andReturn(null);
        expect(mockRequest.getPathInfo()).andReturn("/userid/userid");
        replay(mockRequest);

        DelegationActionFactory factory = new TestDelegationActionFactory(
                mockRequest, trustedPrincipals);
        DelegationAction action = factory.getDelegationAction();
        assertEquals("Wrong action type", GetProxyCertByDN.class, action.getClass());
        assertTrue("wrong target principal", AuthenticationUtil.equals(TEST_X500, action.name));
    }

    @Test
    public void testGetGetProxyCertByUseridWithDaysValidAction()
            throws Exception
    {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        float daysValid = (float) 33.33;
        expect(mockRequest.getParameter("daysValid")).andReturn("33.33");
        expect(mockRequest.getPathInfo()).andReturn("/userid/userid");
        replay(mockRequest);

        DelegationActionFactory factory = new TestDelegationActionFactory(
                mockRequest, trustedPrincipals);
        DelegationAction action = factory.getDelegationAction();
        assertEquals("Wrong action type", GetProxyCertByDN.class, action.getClass());
        assertEquals(daysValid, action.daysValid, 0.000001);
    }

    @Test
    public void testGetGetProxyCertByDNWithWrongDaysValidAction()
            throws Exception
    {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        float daysValid = (float) -33.33;
        expect(mockRequest.getParameter("daysValid")).andReturn("-33.33");
        expect(mockRequest.getPathInfo()).andReturn("/dn/"+TEST_X500.getName());
        replay(mockRequest);

        DelegationActionFactory factory = new TestDelegationActionFactory(
                mockRequest, trustedPrincipals);
        try
        {
            DelegationAction action = factory.getDelegationAction();
            Assert.fail("expected IllegalArgumentException, got: " + action.getClass().getName());
        }
        catch(IllegalArgumentException expected)
        {
            
        }
        
    }

    @Test
    public void testGetGetProxyCertByDNWithWrongDays2ValidAction()
            throws Exception
    {
        HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
        expect(mockRequest.getParameter("daysValid")).andReturn("WRONGNUMBER");
        expect(mockRequest.getPathInfo()).andReturn("/dn/"+TEST_X500.getName());
        replay(mockRequest);

        DelegationActionFactory factory = new TestDelegationActionFactory(
                mockRequest, trustedPrincipals);
        try
        {
            DelegationAction action = factory.getDelegationAction();
            Assert.fail("expected IllegalArgumentException, got: " + action.getClass().getName());
        }
        catch(IllegalArgumentException expected)
        {
            
        }
    }

}
