# Trust Anchor: https://127.0.0.1:7003
# OpenID Provider: https://127.0.0.1:4004
# OpenID Relying Party: https://127.0.0.1:4002
# Trust Mark Issuer: https://127.0.0.1:6000

# Get the entity configuration
./get_entity_configuration.py -k -t trust_anchor_local.json https://127.0.0.1:4002

# Get subordinate statement from superior
./get_subordinate_statement.py -k -t trust_anchor_local.json -s https://127.0.0.1:7003 https://127.0.0.1:4002

# Get Trust Chain
./get_trust_chains.py -k -t trust_anchor_local.json https://127.0.0.1:4002
./get_trust_chains.py -k -t trust_anchor_local.json https://127.0.0.1:4004

# Get new trust mark
./get_trust_mark.py -k -t trust_anchor_local.json -i https://refeds.org/category/personalized -s https://127.0.0.1:4002 https://127.0.0.1:6000

# Check Trust Mark status
./get_trust_mark_status.py -k -t trust_anchor_local.json -i https://refeds.org/category/personalized
  -s https://127.0.0.1:4002 https://127.0.0.1:6000

# List subordinates
./list_subordinates.py -k -t trust_anchor_local.json https://127.0.0.1:7003