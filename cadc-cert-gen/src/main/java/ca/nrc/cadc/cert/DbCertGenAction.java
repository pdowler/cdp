/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2011.                            (c) 2011.
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

import javax.security.auth.x500.X500Principal;
import javax.sql.DataSource;

import org.apache.log4j.Logger;
import org.springframework.jdbc.core.JdbcTemplate;

import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.db.ConnectionConfig;
import ca.nrc.cadc.db.DBConfig;
import ca.nrc.cadc.db.DBUtil;
import ca.nrc.cadc.util.ArgumentMap;
import java.net.URI;
import java.util.Iterator;
import java.util.List;

/**
 * 
 * @author pdowler
 */
public abstract class DbCertGenAction extends AbstractCertGenAction
{
    private static Logger LOGGER = Logger.getLogger(DbCertGenAction.class);

    protected String server = "SYBASE"; // default server
    protected String database = "archive"; // default database
    
    // datasource to the database
    protected DataSource ds;

    protected static final String TMP_TABLE = "#tmptable";

    //public static final String GENERATE_DN_Q = "select dbo.genDN(?)";

    protected DbCertGenAction(URI serviceID)
    {
        super(serviceID);
    }
    
    @Override
    public boolean init(final ArgumentMap argMap) throws IOException
    {
        if (!super.init(argMap))
        {
            return false;
        }
        initDbConnection(argMap);
        return true;
    }

    private void initDbConnection(ArgumentMap argMap) throws IOException
    {
        if (argMap.getValue(Main.ARG_DB) != null)
        {
            database = argMap.getValue(Main.ARG_DB);
            if (database.length() < 2)
            {
                throw new IllegalArgumentException("Argument "
                        + Main.ARG_DB + "("
                        + argMap.getValue(Main.ARG_DB)
                        + ") invalid");
            }
        }

        if (argMap.getValue(Main.ARG_SERVER) != null)
        {
            server = argMap.getValue(Main.ARG_SERVER);
            if (server.length() < 2)
            {
                throw new IllegalArgumentException("Argument "
                        + Main.ARG_SERVER + "("
                        + argMap.getValue(Main.ARG_SERVER)
                        + ") invalid");
            }
        }

        final DBConfig dbrc = new DBConfig();
        LOGGER.debug("dbrc=" + dbrc);
        final ConnectionConfig conCfg = dbrc.getConnectionConfig(server,
                database);
        LOGGER.info("Database name: " + database);
        LOGGER.info("Database server: " + server);
        LOGGER.debug("conCfg=" + conCfg);
        ds = DBUtil.getDataSource(conCfg);
        LOGGER.debug("ds=" + ds);
    }

    /**
     * Returns DN of a cadc user
     *
     * @param userId The HTTP Principal to get the DN for.
     * @return X500Principal, or null.
     */
    @Override
    protected X500Principal getCertificateDN(HttpPrincipal userId)
    {
        final JdbcTemplate jdbc = new JdbcTemplate(ds);

        @SuppressWarnings("unchecked")
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT " ).append(database).append(".dbo.genDN(?)");
        String sql = sb.toString();
        LOGGER.debug("getCertificateDN: " + sql);
        final String userDN = (String) jdbc.queryForObject(sql, new Object[]{ userId.getName()}, String.class);

        X500Principal ret = null;
        if (userDN != null)
            ret = new X500Principal(userDN);
        LOGGER.debug("getCertificateDN: " + userId + " -> " + ret);
        return ret;
    }

    @Override
    protected X500Principal[] getExpiring(int expire)
    {
        // @formatter:off
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT canon_dn" + " FROM ").append(database).append(".dbo.x509_certificates");
        sb.append(" WHERE canon_dn like 'cn=%&____,ou=cadc,o=hia,c=ca' escape '&'");
        sb.append(" AND datediff(dd, current_date(), exp_date) < ? ");
        String query = sb.toString();
        LOGGER.debug("getExpiringCADC: " + query);
        
        // @formatter:on
        JdbcTemplate jdbc = new JdbcTemplate(ds);
        @SuppressWarnings(value = "unchecked")
        List<String> rsList = (List<String>) jdbc.queryForList(query, new Object[]{expire}, String.class);
        X500Principal[] result = new X500Principal[rsList.size()];
        Iterator<String> it = rsList.iterator();
        for (int i = 0; i < result.length; i++)
        {
            result[i] = new X500Principal(it.next());
        }
        return result;
    }

}
