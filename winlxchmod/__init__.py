# -*- coding: utf-8 -*-
"""winlxchmod module.

Module for working with file permissions.

Windows game plan:
1. Find out owner & group
2. Go through each ACE
   - If owner, set owner permissions
   - If SYSTEM, ignore
   - If group, set group permissions
   - If other, set other permissions

Windows Directory:
  -Flags 0x13
     OBJECT_INHERIT_ACE
     CONTAINER_INHERIT_ACE
  -mask 0x1f01ff
     DELETE
     READ_CONTROL
     WRITE_DAC
     WRITE_OWNER
     SYNCHRONIZE
     FILE_ADD_SUBDIRECTORY
     FILE_ADD_FILE
     FILE_DELETE_CHILD
     FILE_LIST_DIRECTORY
     FILE_TRAVERSE
     FILE_READ_ATTRIBUTES
     FILE_WRITE_ATTRIBUTES
     FILE_READ_EA
     FILE_WRITE_EA
"""

import os

HAS_PYWIN32 = False
try:
    import ntsecuritycon  # noqa: F401
    import win32security  # noqa: F401
    HAS_PYWIN32 = True
except ImportError:
    pass


__version__ = "0.1.0"


def display_permissions(path):
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


def windows_get_owner(path):
    """Get the file owner."""
    sec_descriptor = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION)
    sid = sec_descriptor.GetSecurityDescriptorOwner()
    print("Owner: ", sid, win32security.LookupAccountSid(None, sid))


def windows_set_permissions(path):
    """Set the file permissions."""    
    user_x = "UserX"
    user_y = "UserY"

    entries = [{'AccessMode': win32security.GRANT_ACCESS,
                'AccessPermissions': 0,
                'Inheritance':
                    win32security.CONTAINER_INHERIT_ACE |
                    win32security.OBJECT_INHERIT_ACE,
                'Trustee': {'TrusteeType': win32security.TRUSTEE_IS_USER,
                            'TrusteeForm': win32security.TRUSTEE_IS_NAME,
                            'Identifier': ''}}
               for i in range(2)]

    entries[0]['AccessPermissions'] = (ntsecuritycon.GENERIC_READ |
                                       ntsecuritycon.GENERIC_WRITE)
    entries[0]['Trustee']['Identifier'] = user_x
    entries[1]['AccessPermissions'] = ntsecuritycon.GENERIC_ALL
    entries[1]['Trustee']['Identifier'] = user_y

    sec_descriptor = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION)
    dacl = sec_descriptor.GetSecurityDescriptorDacl()
    dacl.SetEntriesInAcl(entries)
    win32security.SetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION |
        win32security.UNPROTECTED_DACL_SECURITY_INFORMATION,
        None, None, dacl, None)


def windows_remove_ace(path):
    """Remove the ace for the given users."""
    if not os.path.exists(path):
        raise FileNotFoundError('Path %s could not be found.' % path)
    total = 0
    usernames = ['Users']
    for username in usernames:
        userx, domain, utype = win32security.LookupAccountName("", username)
        print("Domain:", domain, utype)
        sec_descriptor = win32security.GetFileSecurity(
            path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sec_descriptor.GetSecurityDescriptorDacl()
        num_delete = 0
        for index in range(0, dacl.GetAceCount()):
            ace = dacl.GetAce(index - num_delete)
            if userx == ace[2]:
                dacl.DeleteAce(index - num_delete)
                num_delete += 1
                total += 1
        if num_delete > 0:
            sec_descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                path, win32security.DACL_SECURITY_INFORMATION, sec_descriptor)
    if total > 0:
        return True
    return False
