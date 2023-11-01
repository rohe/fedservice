# Federation example

This set of directories allows you to set up 2 federations, together
containing two RPs, an OP, two intermediates and 2 trust anchors.

The trust anchors controls two federations (SEID and SWAMID).

The two organizations (UMU&LU) both belong to both federations.

UMU has one subordinate, an OP.
LU has two subordinates; one RP that does automatic registration and another
that does explicit registration.

# Setting up the test federations

There is a set of information that must be the same in different places in
the setup. For instance must the keys in the trust_roots in a leaf entity
correspond to the keys owned by the trusted anchors.

Subordinates must also be registered with their authorities.

All of this can be accomplished by using the script `setup.py`

# Testing and verifying the example federation

## Starting/stopping entities

For the commands below to work you are supposed to
stand in the fedservice/example directory.

A simple script for starting/stopping entities:

    ./exec.py start rpa rpa op lu umu seid swamid

This will start all entities in the example federations.
If you want to look at the layout of the federation look at the 
_Federation Example.jpg_ file.

The different entities are:

    RPA
        RP that uses automatic registration
    RPE
        RP that uses explicit registration
    OP
        An OP
    UMU
        An intermediate representing an organization
    LU
        Another intermediate representinng anothe organization
    SEID
        A trust anchor
    SWAMID
        Another trust anchor

Both UMU and LU are members of both federations.

Stopping an entity is as simple as starting it:

    ./exec.py kill RPA

The above command will kill only the RPA entity.

## Displaying an entity's entity statement

For this you can use the `display_entity.py` script:

    ./display_entity.py https://127.0.0.1:5000

Will display the Entity Configuration of the entity that has the provided entity_id.
If the entity is an intermediate or trust anchor, that is has subordinates,
it will also list the subordinates. 
As UMU is the superior of the OP if you do:

    ./display_entity.py https://127.0.0.1:6002

You will get a list of 2 entities: https://127.0.0.1:6002 (UMU)
and https://127.0.0.1:5000 (OP).

## Parsing trust chains.

To do this you use _get_chains.py_

    ../script/get_chains.py -k -t trust_anchors.json -o openid_provider -e federation_entity https://127.0.0.1:5000

* -k : Don't try to verify the certificate used for TLS
* -t : A JSON file with a list of trust anchors.
* -o : The entity type of the entity you want to see
* -e : Own entity type
* The entity ID of the target

This will list the entity statements of the entities in the collected trust 
chains. Each list will start with the trust anchor and then list the
intermediates and finally the leaf in order.

If you do:

    ./exec.py start OP UMU LU SWAMID SEID
    ../script/get_chains.py -k -t trust_anchors.json -o openid_provider -e federation_entity https://127.0.0.1:5000

You will see 2 list each with 3 entities in it.
