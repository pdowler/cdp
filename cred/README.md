# Credential Delegation Protocol service (cred)

## configuration
See the <a href="https://github.com/opencadc/docker-base/tree/master/cadc-tomcat">cadc-tomcat</a> image docs 
for expected deployment and general config requirements.

The following configuration files must be available in the /config directory.

### catalina.properties
When running cred.war in tomcat, parameters of the connection pool in META-INF/context.xml need
to be configured in catalina.properties:
```
# database connection pools
org.opencadc.cred.maxActive={max connections for cred admin pool}
org.opencadc.cred.username={username for cred admin pool}
org.opencadc.cred.password={password for cred admin pool}
org.opencadc.cred.url=jdbc:postgresql://{server}/{database}
```

The `cred` account owns and manages (create, alter, drop) inventory database objects and manages
all the content (insert, update, delete). The database is specified in the JDBC URL and the schema 
name is specified in the cred.properties (below). Failure to connect or initialize the database 
will show up in logs and in the VOSI-availability output.

See <a href="https://github.com/opencadc/docker-base/tree/master/cadc-tomcat">cadc-tomcat</a>
for system properties related to the deployment environment.

See <a href="https://github.com/opencadc/core/tree/master/cadc-util">cadc-util</a>
for common system properties.

`dap` includes multiple IdentityManager implementations to support authenticated access:
 - See <a href="https://github.com/opencadc/ac/tree/master/cadc-access-control-identity">cadc-access-control-identity</a> for CADC access-control system support.
 - See <a href="https://github.com/opencadc/ac/tree/master/cadc-gms">cadc-gms</a> for OIDC token support.

### cred.properties

The configuration in cred.properties configures access to the service and some limits.

```
# optional: users (one per line, multiple allowed) who are allowed to create certificates for other users
org.opencadc.cred.delegate.allowedUser = {user identity}

# users (one per line, multiple allowed) who are allowed to get certificates for other users
org.opencadc.cred.proxy.allowedUser = {user identity}

# maximum lifetime (in days, floating point) of retrieved proxy certifciates
org.opencadc.cred.proxy.maxDaysValid = {time in days}
```

### example cred.properties entry section:
```
org.opencadc.cred.delegate.allowedUser = cn=generate,ou=acme,o=example,c=com 
org.opencadc.cred.delegate.allowedUser = cn=alt,ou=acme,o=example,c=com

org.opencadc.cred.proxy.allowedUser = cn=getproxy,ou=acme,o=example,c=com
org.opencadc.cred.proxy.allowedUser = cn=alt,ou=acme,o=example,c=com

org.opencadc.cred.proxy.maxDaysValid = 0.5
```

### cadc-log.properties (optional)
See <a href="https://github.com/opencadc/core/tree/master/cadc-log">cadc-log</a> for common 
dynamic logging control.

### cadc-vosi.properties (optional)
See <a href="https://github.com/opencadc/reg/tree/master/cadc-vosi">cadc-vosi</a> for common 
service state control.

### cadcproxy.pem (optional)
This client certificate is used to make authenticated server-to-server calls for system-level A&A purposes.

## building
```
gradle clean build
docker build -t cred -f Dockerfile .
```

## checking it
```
docker run -it cred:latest /bin/bash
```

## running it
```
docker run --user tomcat:tomcat --volume=/path/to/external/config:/config:ro --name cred cred:latest
```


