# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# Internal configuration options
SYSCHECK_DEBUG = 'syscheck.debug'
SYMLINK_SCAN_INTERVAL = 'syscheck.symlink_scan_interval'

# Attributes constants.
ATTR_SHA1SUM = 'hash_sha1'
ATTR_MD5SUM = 'hash_md5'
ATTR_SHA256SUM = 'hash_sha256'
ATTR_SIZE = 'size'
ATTR_CHECKSUM = 'checksum'
ATTR_TYPE = 'type'
ATTR_OWNER = ['uid', 'user_name']
ATTR_GROUP = ['gid', 'group_name']
ATTR_PERM = 'perm'
ATTR_ATTRS = 'attributes'
ATTR_MTIME = 'mtime'
ATTR_INODE = 'inode'
ATTR_ALL = [ATTR_SHA256SUM, ATTR_SHA1SUM, ATTR_MD5SUM, ATTR_SIZE, ATTR_OWNER,
            ATTR_GROUP, ATTR_PERM, ATTR_ATTRS, ATTR_MTIME, ATTR_INODE]
ATTR_SUM = [ATTR_SHA1SUM, ATTR_SHA256SUM, ATTR_MD5SUM]
