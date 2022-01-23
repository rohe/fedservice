# Federation enabled Oidc OP.

This directory contains all the necessary files to run a
single instance OP. The OP is not set up to remember things between runs.
So everytime you restart it, it will have forgotten what happened last
time it ran.

## Configuration files

### conf.json
This is the main configuration file. 
It's the same as for a normal OP except for a section
labeled **federation** and another named 
**add_on:automatic_registration**.

In **federation** there are specifications of _entity_id_,
the federation keys (_keys_), _trusted_roots_, _authority_hints_.
All of those you can find in the federation specification.
What's special here is _priority_ which is an ordered list of
the trusted roots in order of priority and _entity_type_, 
_opponent_entity_type_ which specifices what kind of entity the OP
is (openid_provider) and what kind of entity it is expected to
talk to (openid_relying_party). The labels are the metadata type identifiers
used in section 4 of the specification.

**automatic_registration** deals with support for automatic registration.

### authority_hints.json

References from conf.json contains a list of the entity's authority hints.

### trusted_roots.json

Contains a dictionary where the keys are the entity IDs of the trusted roots
and the values are the keys of the trusted root.

### passwd.json

A simple dictionary with the user names as keys and passwords as values

### user.json

Another dictionary with user names as keys and user information as values.

## Dictionaries

### certs

This is where the TLS certificates are kept.

### private

The entity's private keys

### static

The entity's public keys

### templates

HTML templates used as bases for pages the server presents to the user.

## How to run it:
````
./op.py conf.json 
````
