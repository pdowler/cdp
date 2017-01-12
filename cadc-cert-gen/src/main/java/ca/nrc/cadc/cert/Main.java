/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2010.                            (c) 2010.
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

package ca.nrc.cadc.cert;

import java.io.IOException;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

import ca.nrc.cadc.auth.CertCmdArgUtil;
import ca.nrc.cadc.util.ArgumentMap;
import ca.nrc.cadc.util.LogArgUtil;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Main class for the CertGenerator Discovery Agent. The DA generates
 * certificates for CADC users, signs them with the provided CADC key and
 * persists them in the DB.
 */
public class Main
{

    private static Logger LOGGER = Logger.getLogger(Main.class);

    public static final String ARG_HELP = "help";
    public static final String ARG_H = "h";
    public static final String ARG_SERVER = "server";
    public static final String ARG_DB = "database";

    public static final String ARG_SIGNED_CERT = "signingCert";
    public static final String ARG_DRYRUN = "dryrun";

    public static final String ARG_EXPIRING = "expiring";
    public static final String ARG_USERID = "userid";

    public static final String ARG_RESOUIRCE_ID = "resourceID";
    
    public static final int STATUS_FAIL = 1; // exit code for failure
    public static final int STATUS_OK = 0; // exit code for successful execution
    protected static final int DEFAULT_EXPIRE = 30; // Default to 30 days

    // authenticated subject
    protected static Subject subject;
    private ArgumentMap argMap;

    public Main()
    {
    }

    /**
     * @param args Command arguments.
     */
    public static void main(String[] args)
    {
        int exitCode;
        try
        {
            Main da = new Main();
            exitCode = da.doit(args);
        }
        catch (Exception e)
        {
            LOGGER.error(e);
            exitCode = STATUS_FAIL;
        }
        System.exit(exitCode);
    }

    private int doit(final String[] args) throws Exception
    {
        LogArgUtil.initialize(new String[]
        {
            "ca.nrc.cadc.cert",
            "ca.nrc.cadc.cred",
            "ca.nrc.cadc.net"
                
        }, args);
        
        this.argMap = new ArgumentMap(args);
        if (this.argMap.isSet(ARG_HELP) || this.argMap.isSet(ARG_H))
        {
            usage();
            return STATUS_OK;
        }

        try
        {
            subject = CertCmdArgUtil.initSubject(argMap);
        }
        catch (Exception ex)
        {
            LOGGER.error(ex.getMessage());
            LOGGER.debug("Caused by:", ex);
            usage();
            return STATUS_FAIL;
        }

        CertGenAction command = null;

        String rid = argMap.getValue(ARG_RESOUIRCE_ID);
        if (rid == null)
        {
            usage();
            LOGGER.error("missing required --" + ARG_RESOUIRCE_ID);
            return STATUS_FAIL;
        }
        try
        {
            URI resourceID = new URI(rid);
            command = new CertGenAction(resourceID);
            if (!command.init(argMap))
            {
                usage();
                return STATUS_FAIL;
            }
        }
        catch(URISyntaxException ex)
        {
            LOGGER.error("malformed resourceID: " + rid);
            return STATUS_FAIL;
        }
        catch (IOException e)
        {
            LOGGER.error("Cannot find .dbrc file to connect to the database");
            return STATUS_FAIL;
        }
        catch (IllegalArgumentException ex)
        {
            LOGGER.error("illegal argument(s): " + ex.getMessage());
            if (command != null)
            {
                usage();
            }
            else
            {
                usage();
            }
            return STATUS_FAIL;
        }

        try
        {
            Subject.doAs(subject, command);
        }
        catch (Throwable t)
        {
            LOGGER.error("unexpected failure", t);
            return STATUS_FAIL;
        }

        return STATUS_OK;
    }

    /**
     * Formats the usage message.
     */
    public static void usage()
    {
        //@formatter:off

        String[] um = {
                "",
                "cadc-cert-gen [options] [--dryrun] --resourceID=<CDP service identifier> --expiring=<numDays> --signingCert=<certfile.pem>",
                "    \"renew certificates that will expire within <numDays>\"",
                "    --dryrun - only list the expiring certificates",
                "",
                "  OR",
                "",
                "cadc-cert-gen [options] --userid=<userid> --signingCert=<certfile.pem>",
                "    \"renew certificate for user with userid <userid>\"",
                "",
                "  WHERE",
                "    --resourceID:  specifies the CDP service to use (e.g. ivo://cadc.nrc.ca/cred)",
                "    --signingCert: PEM file containing certificate and key use to sign certificates",
                "",
                "  OPTIONS:",
                "    --server=<server> (default is SYBASE)",
                "    --database=<database> (default is archive)",
                "",
                "  IMPORTANT: the --server/--database must specify the same back-end persistence used",
                "             by the CDP service; the latter is controlled by setting the CADC_CERT_GEN_OPTS",
                "             environment variable in order to subvert the cadc-registry client",
                "",
                "    -h --help: show help",
                "    -v --verbose",
                "    -d --debug",
                "",
                "  Note: Generated certificates have all a lifetime of 365 days."};
        msg(um);
    }

    private static void msg(String[] s)
    {
        for (String line : s)
        {
            msg(line);
        }
    }


    /**
     * encapsulate all messages to console here
     */
    public static void msg(String s)
    {
        System.out.println(s);
    }

}
