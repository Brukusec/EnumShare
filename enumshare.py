import argparse
import os
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, srvs
from impacket.smb3structs import FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE
from impacket.smb3structs import FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE, FILE_ATTRIBUTE_NORMAL
from impacket.smb3structs import SMB2_IL_IMPERSONATION, SMB2_OPLOCK_LEVEL_NONE
from impacket.smb3 import GENERIC_ALL

def listSharesViaSMBConnection(smb_connection):
    shares_info = []
    try:
        rpctransport = transport.SMBTransport(smb_connection.getRemoteName(), smb_connection.getRemoteHost(), filename=r'\srvsvc', smb_connection=smb_connection)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)

        resp = srvs.hNetrShareEnum(dce, 1)
        shares_list = resp['InfoStruct']['ShareInfo']['Level1']['Buffer']

        for share in shares_list:
            share_name = share['shi1_netname'][:-1]
            remark = share['shi1_remark'] if share['shi1_remark'] else ""
            read_perm = checkShareReadPermission(smb_connection, share_name)
            write_perm = checkShareWritePermission(smb_connection, share_name)
            permission = 'Read/Write' if read_perm and write_perm else 'Read' if read_perm else 'Write' if write_perm else 'None'
            shares_info.append((share_name, permission, remark))

        return shares_info

    except Exception as e:
        print(f"Failed to list shares: {e}")
        return []

def checkShareReadPermission(smb_connection, share_name):
    try:
        smb_connection.listPath(share_name, '*')
        return True
    except Exception:
        return False

def checkShareWritePermission(smb_connection, share_name):
    try:
        treeId = smb_connection.connectTree(share_name)
        fileId = smb_connection.createFile(treeId, "\\test.txt",
                                           desiredAccess=GENERIC_ALL,
                                           shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                           creationOption=FILE_NON_DIRECTORY_FILE,
                                           creationDisposition=FILE_OVERWRITE_IF,
                                           fileAttributes=FILE_ATTRIBUTE_NORMAL,
                                           impersonationLevel=SMB2_IL_IMPERSONATION,
                                           securityFlags=0,
                                           oplockLevel=SMB2_OPLOCK_LEVEL_NONE,
                                           createContexts=None)

        smb_connection.closeFile(treeId, fileId)
        smb_connection.deleteFile(share_name, "\\test.txt")
        return True
    except Exception:
        return False

def getBasicServerInfo(smb_connection):
    try:
        server_name = smb_connection.getServerName()
        domain_name = smb_connection.getServerDomain()
        server_os = smb_connection.getServerOS()
        return {
            'server_name': server_name,
            'domain_name': domain_name,
            'server_os': server_os
        }
    except Exception as e:
        print(f"Failed to retrieve basic server info: {e}")
        return {
            'server_name': 'N/A',
            'domain_name': 'N/A',
            'server_os': 'N/A'
        }

def connect_and_list_shares(remote_host, username, password, domain=''):
    smb_connection = SMBConnection(remoteName=remote_host, remoteHost=remote_host)
    try:
        smb_connection.login(user=username, password=password, domain=domain)
        server_info = getBasicServerInfo(smb_connection)
        shares_info = listSharesViaSMBConnection(smb_connection)
        return server_info, shares_info
    except Exception as e:
        print(f"Failed to connect to {remote_host}: {e}")
        return {}, []
    finally:
        smb_connection.logoff()

def process_host(remote_host, username, password, domain):
    server_info, shares_info = connect_and_list_shares(remote_host, username, password, domain)
    
    if server_info:
        print(f"ServerName - {server_info['server_name']} - IP address: {remote_host}")
        print(f"Windows Server Version: {server_info['server_os']}")
    else:
        print("Failed to retrieve server info.")

    print(f"Domain name: {domain if domain else 'N/A'}")
    print(f"Username used: {username}")
    print("\nEnumerated shares:\n")
    print(f"{'Share':<25} | {'Permission':<12} | {'Remark'}")
    print("-" * 60)
    for share_name, permission, remark in shares_info:
        print(f"{share_name:<25} | {permission:<12} | {remark}")
    print("\n" + "="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(description='Enumerate SMB shares on a remote host and check permissions.')
    parser.add_argument('-H', '--hosts', required=True, help='Remote host IP or hostname, or file containing a list of hosts')
    parser.add_argument('-u', '--username', required=True, help='Username for SMB authentication')
    parser.add_argument('-p', '--password', required=True, help='Password for SMB authentication')
    parser.add_argument('-d', '--domain', default='', help='Domain for SMB authentication (optional)')

    args = parser.parse_args()

    hosts = []
    if os.path.isfile(args.hosts):
        with open(args.hosts, 'r') as file:
            hosts = [line.strip() for line in file if line.strip()]
    else:
        hosts = [args.hosts]

    for host in hosts:
        print(f"Processing host: {host}")
        process_host(host, args.username, args.password, args.domain)

if __name__ == '__main__':
    main()
