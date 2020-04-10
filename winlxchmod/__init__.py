# -*- coding: utf-8 -*-
"""winlxchmod module.

Module for working with file permissions.
"""

import os

HAS_PYWIN32 = False
try:
    import ntsecuritycon  # noqa: F401
    import win32security  # noqa: F401
    HAS_PYWIN32 = True
except ImportError:
    pass

WIN_FILE_ACCESS = []
WIN_DIR_ACCESS = []
if HAS_PYWIN32:
    WIN_FILE_ACCESS = [
        0,
        win32security.FILE_GENERIC_EXECUTE,
        win32security.FILE_GENERIC_WRITE,
        (
            win32security.FILE_GENERIC_WRITE |
            win32security.FILE_GENERIC_EXECUTE
        ),
        win32security.FILE_GENERIC_READ,
        (
            win32security.FILE_GENERIC_READ |
            win32security.FILE_GENERIC_EXECUTE
        ),
        (
            win32security.FILE_GENERIC_READ |
            win32security.FILE_GENERIC_WRITE
        ),
        win32security.FILE_ALL_ACCESS
    ]

    WIN_DIR_ACCESS = [
        0,
        (
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.GENERIC_EXECUTE
        ),
        (
            ntsecuritycon.DELETE |
            ntsecuritycon.WRITE_DAC |
            ntsecuritycon.WRITE_OWNER |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_ADD_SUBDIRECTORY |
            ntsecuritycon.FILE_ADD_FILE |
            ntsecuritycon.FILE_DELETE_CHILD |
            ntsecuritycon.FILE_WRITE_ATTRIBUTES |
            ntsecuritycon.FILE_WRITE_EA |
            ntsecuritycon.GENERIC_WRITE
        ),
        (
            ntsecuritycon.DELETE |
            ntsecuritycon.WRITE_DAC |
            ntsecuritycon.WRITE_OWNER |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_ADD_SUBDIRECTORY |
            ntsecuritycon.FILE_ADD_FILE |
            ntsecuritycon.FILE_DELETE_CHILD |
            ntsecuritycon.FILE_WRITE_ATTRIBUTES |
            ntsecuritycon.FILE_WRITE_EA |
            ntsecuritycon.GENERIC_WRITE |
            ntsecuritycon.GENERIC_EXECUTE
        ),
        (
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_LIST_DIRECTORY |
            ntsecuritycon.FILE_TRAVERSE |
            ntsecuritycon.FILE_READ_ATTRIBUTES |
            ntsecuritycon.FILE_READ_EA |
            ntsecuritycon.GENERIC_READ
        ),
        (
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_LIST_DIRECTORY |
            ntsecuritycon.FILE_TRAVERSE |
            ntsecuritycon.FILE_READ_ATTRIBUTES |
            ntsecuritycon.FILE_READ_EA |
            ntsecuritycon.GENERIC_READ |
            ntsecuritycon.GENERIC_EXECUTE
        ),
        (
            ntsecuritycon.DELETE |
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.WRITE_DAC |
            ntsecuritycon.WRITE_OWNER |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_ADD_SUBDIRECTORY |
            ntsecuritycon.FILE_ADD_FILE |
            ntsecuritycon.FILE_DELETE_CHILD |
            ntsecuritycon.FILE_LIST_DIRECTORY |
            ntsecuritycon.FILE_TRAVERSE |
            ntsecuritycon.FILE_READ_ATTRIBUTES |
            ntsecuritycon.FILE_WRITE_ATTRIBUTES |
            ntsecuritycon.FILE_READ_EA |
            ntsecuritycon.FILE_WRITE_EA |
            ntsecuritycon.GENERIC_READ |
            ntsecuritycon.GENERIC_WRITE
        ),
        (
            ntsecuritycon.DELETE |
            ntsecuritycon.READ_CONTROL |
            ntsecuritycon.WRITE_DAC |
            ntsecuritycon.WRITE_OWNER |
            ntsecuritycon.SYNCHRONIZE |
            ntsecuritycon.FILE_ADD_SUBDIRECTORY |
            ntsecuritycon.FILE_ADD_FILE |
            ntsecuritycon.FILE_DELETE_CHILD |
            ntsecuritycon.FILE_LIST_DIRECTORY |
            ntsecuritycon.FILE_TRAVERSE |
            ntsecuritycon.FILE_READ_ATTRIBUTES |
            ntsecuritycon.FILE_WRITE_ATTRIBUTES |
            ntsecuritycon.FILE_READ_EA |
            ntsecuritycon.FILE_WRITE_EA |
            ntsecuritycon.GENERIC_READ |
            ntsecuritycon.GENERIC_WRITE |
            ntsecuritycon.GENERIC_EXECUTE |
            ntsecuritycon.GENERIC_ALL
        )
    ]

__version__ = "0.1.0"


def win_get_owner(path):
    """Get the file owner."""
    sec_descriptor = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION)
    sid = sec_descriptor.GetSecurityDescriptorOwner()
    print("Owner: ", sid, win32security.LookupAccountSid(None, sid))
    return sid


def win_get_group(path):
    """Get the file group."""
    sec_descriptor = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.GROUP_SECURITY_INFORMATION)
    sid = sec_descriptor.GetSecurityDescriptorGroup()
    print("Group: ", win32security.LookupAccountSid(None, sid))
    return sid


def win_set_permissions(path, mode):
    """Set the file or dir permissions."""
    if not os.path.exists(path):
        raise FileNotFoundError('Path %s could not be found.' % path)

    if len(mode) != 3:
        raise AttributeError('Mode must be 3 char long, given %s.' % mode)

    _win_set_permissions(path, mode)


def _win_append_ace(ace_list, sid, access):
    trustee = {}
    trustee['MultipleTrustee'] = None
    trustee['MultipleTrusteeOperation'] = 0
    trustee['TrusteeForm'] = win32security.TRUSTEE_IS_SID
    trustee['TrusteeType'] = win32security.TRUSTEE_IS_USER
    trustee['Identifier'] = sid

    ace_list.append({
        'Trustee': trustee,
        'Inheritance': win32security.NO_INHERITANCE,
        'AccessMode': win32security.GRANT_ACCESS,
        'AccessPermissions': access
    })


def _win_set_permissions(path, mode):
    """Set the file permissions."""
    # get rid of all ACEs except system's
    sec_descriptor = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION)
    dacl = sec_descriptor.GetSecurityDescriptorDacl()

    num_delete = 0
    for index in range(0, dacl.GetAceCount()):
        ace = dacl.GetAce(index - num_delete)
        if ace[2] != 'SYSTEM':
            dacl.DeleteAce(index - num_delete)
            num_delete += 1

    if os.path.isfile(path):
        accesses = WIN_FILE_ACCESS
    else:
        accesses = WIN_DIR_ACCESS

    new_aces = []

    # add ACE for owner
    if mode[0] != '0':
        _win_append_ace(
            new_aces, win_get_owner(path), accesses[int(mode[0])])

    # add ACE for group
    if mode[1] != '0':
        _win_append_ace(
            new_aces, win_get_group(path), accesses[int(mode[1])])

    # add ACE for others
    if mode[2] != '0':
        users_sid = win32security.LookupAccountName('', 'Users')[0]
        _win_append_ace(
            new_aces, users_sid, accesses[int(mode[2])])

    # make it real
    dacl.SetEntriesInAcl(new_aces)
    win32security.SetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION |
        win32security.UNPROTECTED_DACL_SECURITY_INFORMATION,
        None, None, dacl, None)


def win_display_permissions(path):
    """Display permissions."""
    if not os.path.exists(path):
        print(path, "does not exist!")
        raise FileNotFoundError('Path %s could not be found.' % path)

    print("On file ", path, "\n")

    # get owner SID
    print("OWNER")
    sec_descriptor = win32security.GetFileSecurity(
        path, win32security.OWNER_SECURITY_INFORMATION)
    sid = sec_descriptor.GetSecurityDescriptorOwner()
    print("  ", win32security.LookupAccountSid(None, sid))

    # get group SID
    print("GROUP")
    sec_descriptor = win32security.GetFileSecurity(
        path, win32security.GROUP_SECURITY_INFORMATION)
    sid = sec_descriptor.GetSecurityDescriptorGroup()
    print("  ", win32security.LookupAccountSid(None, sid))

    # get ACEs
    sec_descriptor = win32security.GetFileSecurity(
        path, win32security.DACL_SECURITY_INFORMATION)
    dacl = sec_descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        print("No Discretionary ACL")
        return

    for ace_no in range(0, dacl.GetAceCount()):
        ace = dacl.GetAce(ace_no)
        print("ACE", ace_no)

        print("  -Type")
        for i in (
                "ACCESS_ALLOWED_ACE_TYPE", "ACCESS_DENIED_ACE_TYPE",
                "SYSTEM_AUDIT_ACE_TYPE", "SYSTEM_ALARM_ACE_TYPE"):
            if getattr(ntsecuritycon, i) == ace[0][0]:
                print("    ", i)

        print("  -Flags", hex(ace[0][1]))
        for i in (
                "OBJECT_INHERIT_ACE", "CONTAINER_INHERIT_ACE",
                "NO_PROPAGATE_INHERIT_ACE", "INHERIT_ONLY_ACE",
                "SUCCESSFUL_ACCESS_ACE_FLAG", "FAILED_ACCESS_ACE_FLAG"):
            if getattr(ntsecuritycon, i) & ace[0][1] == getattr(
                    ntsecuritycon, i):
                print("    ", i)

        print("  -mask", hex(ace[1]))

        # files and directories do permissions differently
        permissions_file = (
            "DELETE", "READ_CONTROL", "WRITE_DAC", "WRITE_OWNER",
            "SYNCHRONIZE", "FILE_GENERIC_READ", "FILE_GENERIC_WRITE",
            "FILE_GENERIC_EXECUTE", "FILE_DELETE_CHILD")
        permissions_dir = (
            "DELETE", "READ_CONTROL", "WRITE_DAC", "WRITE_OWNER",
            "SYNCHRONIZE", "FILE_ADD_SUBDIRECTORY", "FILE_ADD_FILE",
            "FILE_DELETE_CHILD", "FILE_LIST_DIRECTORY", "FILE_TRAVERSE",
            "FILE_READ_ATTRIBUTES", "FILE_WRITE_ATTRIBUTES", "FILE_READ_EA",
            "FILE_WRITE_EA")
        permissions_dir_inherit = (
            "DELETE", "READ_CONTROL", "WRITE_DAC", "WRITE_OWNER",
            "SYNCHRONIZE", "GENERIC_READ", "GENERIC_WRITE", "GENERIC_EXECUTE",
            "GENERIC_ALL")
        if os.path.isfile(path):
            permissions = permissions_file
        else:
            permissions = permissions_dir
            # directories have ACE that is inherited by children within them
            if ace[0][1] & ntsecuritycon.OBJECT_INHERIT_ACE == \
               ntsecuritycon.OBJECT_INHERIT_ACE and ace[0][1] & \
               ntsecuritycon.INHERIT_ONLY_ACE == \
               ntsecuritycon.INHERIT_ONLY_ACE:
                permissions = permissions_dir_inherit

        calc_mask = 0  # see if we are printing all of the permissions
        for i in permissions:
            if getattr(ntsecuritycon, i) & ace[1] == getattr(ntsecuritycon, i):
                calc_mask = calc_mask | getattr(ntsecuritycon, i)
                print("    ", i)
        print("  ", "Calculated Check Mask=", hex(calc_mask))
        print("  -SID\n    ", win32security.LookupAccountSid(None, ace[2]))
