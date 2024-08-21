# cred integration tests

The integration tests lookup and test `ivo://opencadc.org/cred`.

The deployed service must be configued so the identity in 
$A/test-certificates/cred-super.pem is one of the super-users.

To run the tests, ~/.netrc file must have username and password 
that can be used to obtain a token from the local implementation 
of `ivo://ivoa.net/sso#tls-with-password` _and_ that must also 
be one of the configured super-users (not necessarily the same
as the certificate above).

