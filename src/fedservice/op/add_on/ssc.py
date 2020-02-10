"""Support for TLS servers using self-signed certificates."""
import os


def add_ssc_support(federation_entity, **kwargs):
    """

    :param endpoint:
    :param kwargs:
    :return:
    """
    _collector = federation_entity.collector

    _collector.use_ssc = True
    _dir = kwargs.get("ssc_dir", "")
    if _dir.startswith("/"):
        _collector.ssc_dir = _dir
    else:
        _collector.ssc_dir = os.path.join(_collector.cwd, _dir)

    if not os.path.isdir(_collector.ssc_dir):
        os.makedirs(_collector.ssc_dir, exist_ok=True)

    _cert = kwargs.get("client_cert")
    _key = kwargs.get("client_key")

    if _cert and _key:
        _collector.httpc_params['cert'] = (_cert, _key)
    elif _cert:
        _collector.httpc_params['cert'] = _cert