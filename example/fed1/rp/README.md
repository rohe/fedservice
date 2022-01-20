# Federation enabled Oidc RPs.

This directory contains all the necessary files to run two
different types of RPs. One that does explicit client registration
and the other automatic client registration. The RPs is not set up to 
remember things between runs.
So everytime you restart one of them, it will have forgotten what happened last
time it ran. They both use the same set of trusted root and authority hints.

## Configuration files

### conf_expl.json and conf_auto.json

The main configuration files. There are only slight differences between
the two files. Different listening ports, names on key files and the
registration type the RP is suposed to use (_automatic_ or _explicit_).

The configuration file is similar that for a normal RP except for a section
labeled **federation**.

In **federation** there are specifications of _entity_id_,
the federation keys (_keys_), _trusted_roots_, _authority_hints_.
All of those you can find in the federation specification.
What's special here is _priority_ which is an ordered list of
the trusted roots in order of priority and _entity_type_, 
_opponent_entity_type_ which specifices what kind of entity the OP
is (openid_provider) and what kind of entity it is expected to
talk to (openid_relying_party). The labels are the metadata type identifiers
used in section 4 of the specification.

The _entity_id_ specification is open-ended because the RP needs to be
able to construct different entity_ids for different OPs.

### authority_hints.json

References from conf.json contains a list of the entity's authority hints.

### trusted_roots.json

Contains a dictionary where the keys are the entity IDs of the trusted roots
and the values are the keys of the trusted root.

## Dictionaries

### certs

This is where the TLS certificates are kept.

### private

The entity's private keys

### static

The entity's public keys

### templates

HTML templates used as bases for pages the server presents to the user.

## How to run

Running the RP that does automatic client registration

````
rp.py conf_auto.json 
````

or the one doing explicit registration

````
rp.py conf_expl.json 
````
