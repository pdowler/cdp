# Credential Delegation Protocol service (cred)

## configuration

The following configuration files must be available in the /config directory.

### catalina.properties
This file contains java system properties to configure the tomcat server and some of the java
libraries used in the service.

See <a href="https://github.com/opencadc/docker-base/tree/master/cadc-tomcat">cadc-tomcat</a>
for system properties related to the deployment environment.

See <a href="https://github.com/opencadc/core/tree/master/cadc-util">cadc-util</a>
for common system properties.

### cred.properties

The configuration in cred.properties configures access to the service and some limits.

```
# users (one per line, multiple allowed) who are allowed to get certificates for other users
org.opencadc.cred.superUser = {user identity}

# maximum lifetime (in days, floating point) of retrieved proxy certifciates
org.opencadc.cred.maxDaysValid = {time in days}

# size of the generated RSA keys (2048, 4096 ...)
org.opencadc.cred.userKeySize = {2048|4096|...}
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


