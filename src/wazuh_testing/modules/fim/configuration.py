# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# Internal configuration options
SYSCHECK_DEBUG = 'syscheck.debug'
SYMLINK_SCAN_INTERVAL = 'syscheck.symlink_scan_interval'
FILE_MAX_SIZE = 'syscheck.file_max_size'
RT_DELAY = 'syscheck.rt_delay'

# File names
LAST_ENTRY_FILE = 'last-entry.gz'

# Attributes constants.
ATTR_SHA1SUM = 'sha1'
ATTR_MD5SUM = 'md5'
ATTR_SHA256SUM = 'sha256'
ATTR_SIZE = 'size'
ATTR_OWNER = ['uid', 'owner']
ATTR_GROUP = ['gid', 'group']
ATTR_PERM = 'permissions'
ATTR_ATTRS = 'attributes'
ATTR_MTIME = 'mtime'
ATTR_INODE = 'inode'
ATTR_DEVICE = 'device'
ATTR_ALL = [ATTR_SHA1SUM, ATTR_SHA256SUM, ATTR_MD5SUM, ATTR_SIZE, ATTR_OWNER,
            ATTR_GROUP, ATTR_PERM, ATTR_ATTRS, ATTR_MTIME, ATTR_INODE, ATTR_DEVICE]
ATTR_SUM = [ATTR_SHA1SUM, ATTR_SHA256SUM, ATTR_MD5SUM]
