import numbers

def validate_interval_format(interval):
    """Validate that the interval passed has the format in which the last digit is a letter from those passed and
       the other characters are between 0-9."""
    if interval == '':
        return False
    if interval[-1] not in ['s', 'm', 'h', 'd', 'w', 'y'] or not isinstance(int(interval[0:-1]), numbers.Number):
        return False
    return True
