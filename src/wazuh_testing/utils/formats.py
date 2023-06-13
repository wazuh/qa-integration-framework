import numbers

from struct import pack, unpack

def validate_interval_format(interval):
    """Validate that the interval passed has the format in which the last digit is a letter from those passed and
       the other characters are between 0-9."""
    if interval == '':
        return False
    if interval[-1] not in ['s', 'm', 'h', 'd', 'w', 'y'] or not isinstance(int(interval[0:-1]), numbers.Number):
        return False
    return True

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
