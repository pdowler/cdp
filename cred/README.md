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


## integration testing

A client certificates named `cred-test.pem` must exist in the directory $A/test-certificates.
This can be a normal user certificate (or proxy) and is used to delegate (itself) to the cred service (the 
normal use of CDP).

A client certificate named `cred-test-super.pem` must exist in the directory $A/test-certificates and the 
distinguished name must be configured as an `org.opencadc.cred.proxy.allowedUser`. This is used to test that
a special operational user can retrieve a proxy cert for another user.

There is currently no test for `org.opencadc.cred.delegate.allowedUser` as that requires a CA cert in the
test environment and essentially the whole `cadc-cert-gen` functionality.

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

## apply version tags
```bash
. VERSION && echo "tags: $TAGS" 
for t in $TAGS; do
   docker image tag cred:latest cred:$t
done
unset TAGS
docker image list cred
```

