

create table <schema>.X509CertificateChain (
    hash_dn varchar(32) not null primary key,
    canon_dn varchar(512) not null,
    private_key bytea not null,

    exp_date timestamp,
    csr text,
    cert_chain text,
    
    lastModified timestamp not null
);

create unique index x509_canon_dn on <schema>.X509CertificateChain(canon_dn);

create index x509_expiry on <schema>.X509CertificateChain(exp_date);

create index x509_lastModified on <schema>.X509CertificateChain(lastModified);
