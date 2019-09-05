def branch2lists(tree):
    res = []
    (statement, superior) = tree
    if superior:
        for issuer, branch in superior.items():
            _lists = branch2lists(branch)
            for l in _lists:
                l.append(statement)
            if not res:
                res = _lists
            else:
                res.extend(_lists)
    else:
        res.append([statement])
    return res


data = (
    'ITS', {
        'UMU': (
            'ITS_UMU', {
                "SUNET": ('UMU_SUNET', {
                    'SUNET': ('SUNET_SUNET', {})
                }),
                "UNINETT": ('UMU_UNINETT', {
                    'EDUGAIN': ('UNINETT_EDUGAIN', {
                        'EDUGAIN': ('EDUGAIN_EDUGAIN', {})
                    })
                })
            }),
        'UME': (
            'ITS_UME', {
                "SKOLFed": ('UME_SKOL', {
                    'SKOLFed': ('SKOL_SKOL', {})
                })
            }
        ),
        'WAYF': (
            'WAYF_ITS', {
                'WAIF': ("WAYF_WAYF", {})
            }
        )
    }
)

l = branch2lists(data)

print(l)
