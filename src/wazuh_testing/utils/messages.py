# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from struct import pack, unpack


def wazuh_unpack(data, format_: str = "<I"):
    """Unpack data with a given header. Using Wazuh header by default.

    Args:
        data (bytes): Binary data to unpack
        format_ (str): Optional - Format used to unpack data. Default "<I"

    Returns:
        int : Unpacked value
    """
    return unpack(format_, data)[0]


def wazuh_pack(data, format_: str = "<I"):
    """Pack data with a given header. Using Wazuh header by default.

    Args:
        data (int): Int number to pack
        format_ (str): Optional - Format used to pack data. Default "<I"

    Returns:
        (bytes) : Packed value
    """
    return pack(format_, data)
