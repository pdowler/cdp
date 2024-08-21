# X509 Client Certificate Generation service (cred)

The `cred` service can generate internally signed client certificates for users so that
services can make transitive calls to other services _as the user_ that use/share the same 
AAI system. 

This is a replacement for the the previous IVOA CDP (Credential Delegation Protocol)
that is becoming impractical to operate. CDP relies on the use of client proxy certificates
and it has become increasingly hard to make proxy certificates work with current HTTP frontends
that use openssl because the old `OPENSSL_ALLOW_PROXY_CERTS=1` mechanism has been removed.

This service generates real (non-proxy) short-lived client certificates for users that can be
used as a form of authentication.  In addition to transitive API calls to _local_ services,
these certificates may be a good option for non-interactive processes (e.g. batch processing)
where a longer lived credential is desireable.

## configuration

The following configuration files must be available in the /config directory.

### catalina.properties
This file contains java system properties to configure the tomcat server and some of the java
libraries used in the service.

See <a href="https://github.com/opencadc/docker-base/tree/master/cadc-tomcat">cadc-tomcat</a>
for system properties related to the deployment environment.

See <a href="https://github.com/opencadc/core/tree/master/cadc-util">cadc-util</a>
for common system properties.

`cred` includes multiple IdentityManager implementations to support authenticated access:
 - See <a href="https://github.com/opencadc/ac/tree/master/cadc-access-control-identity">cadc-access-control-identity</a> for CADC access-control system support.
 - See <a href="https://github.com/opencadc/ac/tree/master/cadc-gms">cadc-gms</a> for OIDC token support.
 
Experimental/backwards-compatibility: When the local AAI system includes support for form-based 
authentication using standardID `ivo://ivoa.net/sso#tls-with-password` _and_ the token returned 
can be validated by the Identitymanager, `cred` also supports HTTP Basic Auth. The deployer *MUST* 
set the following system property to enable Basic auth:
```
ca.nrc.cadc.auth.PrincipalExtractor.allowBasicATP=true
```
This has tested using the `ACIdentityManager` but will not work with the  StandardIdentityManager as-is
because (i) OIDC doesn't have a simple form-based login and (ii) users in OIDC generally do not have the
X500Principal identity associated with their account that is required by the `cred` service.

### cadc-registry.properties
See <a href="https://github.com/opencadc/reg/tree/master/cadc-registry">cadc-registry</a>.

### cred.properties

The configuration in cred.properties configures access to the service and some limits.
```
# users (one per line, multiple allowed) who are allowed to get certificates for other users
org.opencadc.cred.superUser = {user identity}

# maximum lifetime (in days, floating point) of retrieved proxy certificates
org.opencadc.cred.maxDaysValid = {time in days}
```

### example cred.properties entry section:
```
org.opencadc.cred.superUser = cn=generate,ou=acme,o=example,c=com 
org.opencadc.cred.superUser = cn=alt,ou=acme,o=example,c=com

org.opencadc.cred.proxy.maxDaysValid = 7.0
```

### signcert.pem
This is the certificate used to sign generated certificates returned by the `cred` service. This may be
an internal self-signed certificate; in that case, it will need to be included in the CA certificate bundle
of any services (front end) that are expected to verify the generated certificates (usually, just the HTTP
front end that terminates SSL).

### cadc-log.properties (optional)
See <a href="https://github.com/opencadc/core/tree/master/cadc-log">cadc-log</a> for common 
dynamic logging control.

### cadc-vosi.properties (optional)
See <a href="https://github.com/opencadc/reg/tree/master/cadc-vosi">cadc-vosi</a> for common 
service state control.

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


