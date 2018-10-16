#!/usr/bin/env python3

# Roles
#  RP: https://127.0.0.1/com/rp
#  OP: https://127.0.0.1/org/op
#  comA: https//127.0.0.1/com/a
#  orgB: https//127.0.0.1/org/b
#  fed: https://127.0.0.1/fed
#
# RP: Get and evaluate OPs entity statement starting with the issuer_id
# Chose a set of trust paths that ends in trusted trust roots.

# RP: based on the OPs metadata and the client preferences construct a
# metadata statement that fulfills most of the demands.

# RP: Construct entity statement and send it as a client request to the OP.
# The set of authority_hints should be chosen to reference trust roots that
# the OP trusts.

#  OP: Collect trust chains, chose one and flatten metadata.
#      construct client registration response and return to RP

