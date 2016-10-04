# cadc-cert-gen

Simple tool to enable someone to use their cadc-cdp-server based CDP service as an internal CA to 
provide local user certificates.

Known Issues:
- several hard-coded settings and behaviours make this unusable until some refactoring is done
- shares knowledge of back-end DB implementation used in cadc-cdp-server to query the RDBMS table
  to find expiring certificates
- only looks for expiring certificates that match a hard-coded CADC internal CA distinguished name pattern

