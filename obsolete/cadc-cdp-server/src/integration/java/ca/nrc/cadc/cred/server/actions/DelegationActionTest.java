package ca.nrc.cadc.cred.server.actions;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.security.AccessControlException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.junit.Test;

import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.server.CertificateDAO;
import ca.nrc.cadc.util.Log4jInit;
import org.apache.log4j.Level;

public class DelegationActionTest
{
    static File certFile;

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.cred", Level.DEBUG);
        
        certFile = new File("build/test/class/proxy.pem");
    }

    @Test
    public void testTrustedPrincipals() throws Exception
    {
        X500Principal target = new X500Principal("cn=foo,ou=cadc,o=nrc,c=ca");
        Subject subject = SSLUtil.createSubject(certFile);
       
        X500Principal principal =  subject.getPrincipals(X500Principal.class).iterator().next();
        Map<X500Principal, Float> trustedPrincipals = new HashMap<X500Principal, Float>();
        trustedPrincipals.put(principal, Float.MAX_VALUE);

        DelegationAction delegationAction = new DelegationStub(target, 0.1f, trustedPrincipals);
        Subject.doAs(subject, delegationAction);
    }

    @Test
    public void testUntrustedPrincipals() throws Exception
    {
        X500Principal target = new X500Principal("cn=foo,ou=cadc,o=nrc,c=ca");
        
        X500Principal principal = new X500Principal("cn=somebody else,ou=cadc,o=nrc,c=ca");
        Map<X500Principal, Float> trustedPrincipals = new HashMap<X500Principal, Float>();
        trustedPrincipals.put(principal, new Float(0.0));
        
        Subject subject = SSLUtil.createSubject(certFile);

        DelegationAction delegationAction = new DelegationStub(target, 0.1f, trustedPrincipals);
        try
        {
            Subject.doAs(subject, delegationAction);
            assertTrue("Expected exception not thrown.", false);
        }
        catch (AccessControlException expected)
        {
            
        }
    }

}

class TestConfig extends CertificateDAO.CertificateSchema
{
    TestConfig() { super("DSNAME", "DATABASE", "SCHEMA"); }
}
class DelegationStub extends DelegationAction
{
    public DelegationStub(X500Principal name, float daysActive,
            Map<X500Principal, Float> trustedPrincipals)
    {
        super(name, daysActive, trustedPrincipals, new CertificateDAO(new TestConfig()));
    }

    @Override
    public X509CertificateChain getCertificate(X500Principal name)
            throws Exception
    {
        return null;
    }
}
