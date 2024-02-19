#################################################
OpenID federation as Wallet ecosystem trust layer
#################################################

The federation consists of the following entities:

* trust anchor
* trust mark issuer
* wallet provider

In this example all the entities are running on the same machine.
It is of course not necessary to do so.
If you run the entities on separate machines you have to move the necessary
files inbetween them.

Start by setting up the trust anchor.

Trust Anchor
------------

The configuration of the trust anchor can be found in the *trust_anchor* directory.
Consists of two files

* conf.json
    The configuration of the entitys components
* views.py
    The webserver's (Flask) interface configuration

The existence of those two file with exactly those names are necessary for this
to work.

To start running the trust anchor you have to do::

    ./entity.py trust_anchor

This will create a number of things in the *trust_anchor* directory

* private
    Where the JWKS representation of the private federation keys are kept
* static
    Where the JWKS representation of the public federation keys are kept
* subordinate
    A directory where information about subordinates are to be kept
* trust_mark_issuers
    A directory where information about trust mark issuers are kept.
* debug.log
    A log file

All entities in the federation has to have some information about the
trust mark. The information to pass along is collected by doing::

    ./get_info.py -k -t https://127.0.0.1:7003 > trust_anchor.json

This must be done while the Trust anchor is running.

Now your done with phase 1 concerning the trust anchor. So you can
kill that process for the time being.

Trust Mark Issuer
-----------------

To start running the trust mark issuer you have to do::

    ./entity.py trust_mark_issuer

A slightly different set of files/directories has been added

* private
    Where the JWKS representation of the private federation keys are kept
* static
    Where the JWKS representation of the public federation keys are kept
* trust_anchors
    A directory where information about trust anchors are kept
* authority_hints
    A file containing entity_ids of this entity's authority hints.
    Note that there is also a authority_hints.lock file present you can safely
    ignore it.
* debug.log
    A log file

Now four things have to happen::

1. Adding information about trust anchors
2. Add authority hints
3. Add information about the trust mark issuer as a subordinate to the trust anchor
4. Add information about the trust mark issuer as a trust mark issuer to the trust anchor.

The first two are simply::

    ./add_info.py -s trust_anchor.json -t trust_mark_issuer/trust_anchors
    echo -e "https://127.0.0.1:7003" >> trust_mark_issuer/authority_hints

The third would look like this::

    ./get_info.py -k -s https://127.0.0.1:6000 > tmp.json
    ./add_info.py -s tmp.json -t trust_anchor/subordinates

The fourth is presently done like this (may change in the future)::

    ./issuer.py trust_mark_issuer > tmp.json
    ./add_info.py -s tmp.json -t trust_anchor/trust_mark_issuers

That should do it for the trust mark issuer.
If you now restart it it should have all the necessary information to be part of the federation.

Wallet Provider
---------------

Much the same as for the trust mark issuer.
To start running the wallet provider you have to do::

    ./entity.py wallet_provider

A slightly different set of files/directories has been added

* private
    Where the JWKS representation of the private federation keys are kept
* static
    Where the JWKS representation of the public federation keys are kept
* trust_anchors
    A directory where information about trust anchors are kept
* authority_hints
    A file containing entity_ids of this entity's authority hints.
    Note that there is also a authority_hints.lock file present you can safely
    ignore it.
* debug.log
    A log file

Now four things have to happen::

1. Adding information about trust anchors
2. Add authority hints
3. Add information about the wallet provider as a subordinate to the trust anchor

The first two are simply::

    ./add_info.py -s trust_anchor.json -t wallet_provider/trust_anchors
    echo -e "https://127.0.0.1:7003" >> wallet_provider/authority_hints

The third would look like this::

    ./get_info.py -k -s https://127.0.0.1:5001 > tmp.json
    ./add_info.py -s tmp.json -t trust_anchor/subordinates


That should do it for the wallet provider.
If you now restart it it should have all the necessary information to be part of the federation.

Finalizing the setup
--------------------

At this point, if you have followed the steps above, you should restart the trust anchor.
I should not be necessary to do so but just in case.


Creating a trust mark for an entity
-----------------------------------

For this the script *create_trust_mark.py* is included.
Typical usage::

    ./create_trust_mark.py -d trust_mark_issuer -m http://example.com/trust_mark_id -e https://127.0.0.1:6000


usage: create_trust_mark.py [-h] [-d DIR_NAME] [-e ENTITY_ID] [-m TRUST_MARK_ID] ::

    options:
      -h, --help            show this help message and exit
      -d DIR_NAME, --dir_name DIR_NAME
      -e ENTITY_ID, --entity_id ENTITY_ID
      -m TRUST_MARK_ID, --trust_mark_id TRUST_MARK_ID
