drop function get_certificate_chain(uuid);
drop function get_certificate_updates(text[], timestamp);

drop table x509_certificate_subscriptions;
drop table x509_certificates;
drop table x509_private_keys;

drop type private_key_type;