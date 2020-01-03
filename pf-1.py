#!/usr/bin/python
#coding: utf-8

import sys
import os
import MySQLdb as mdb

config = {'iptables': '/usr/bin/sudo /sbin/iptables'}

class IPTablesFailure (Exception):
    pass

def operating_db ( sql = '' ):
    db_user = 'root'
    db_password = '123456'
    db_hostname = '127.0.0.1'
    db_name = 'vpn_permission'
    con = mdb.connect(db_hostname, db_user, db_password , db_name , charset="utf8")
    try:
        with con:
            cur = con.cursor(mdb.cursors.DictCursor)
            cur.execute (sql)
            rows = cur.fetchall()
            return rows
    except mdb.Error, e:
        print "Error %d: %s" % (e.args[0],e.args[1])
        return False
    if con_db:
        con_db.close()

def get_curr_rule_num ():
    config['iptables']
    Chain_INPUT_NUM = os.popen(config['iptables'] + ' -L INPUT --line-numbers | grep "reject-with icmp-host-prohibited" | cut -d" " -f1').readlines()
    Chain_FORWARD_NUM = os.popen(config['iptables'] + ' -L FORWARD --line-numbers | grep "reject-with icmp-host-prohibited" | cut -d" " -f1').readlines()
    if Chain_INPUT_NUM == []:
        Chain_INPUT_NUM = 'Null'
    else:
        Chain_INPUT_NUM = int (Chain_INPUT_NUM[0])
    if Chain_FORWARD_NUM == []:
        Chain_FORWARD_NUM = 'Null'
    else:
        Chain_FORWARD_NUM = int (Chain_FORWARD_NUM[0])
    return Chain_INPUT_NUM,Chain_FORWARD_NUM

def iptables (args, raiseEx=True):
    command = "%s %s" % (config['iptables'], args)
    print command
    status = os.system(command)
    if status == -1:
        raise IPTablesFailure ("Could not run iptables: %s" % (command,))
    status = os.WEXITSTATUS(status)
    if raiseEx and (status != 0):
        raise IPTablesFailure ("iptables exited with status %d (%s)" % (status, (config['iptables'], args)))
    if (status != 0):
        return False
    return True

def build_rule(chain, client_ip, dst_ip):
    if dst_ip != '':
        rule = "-A %s -s %s -d %s -j ACCEPT" % (chain, client_ip, dst_ip)
        iptables (rule)
    else:
        rule = "-A %s -s %s -j ACCEPT" % (chain, client_ip)
        iptables (rule)

def load_rules (client_ip, client_name):
    sql = 'SELECT vpn_allow_rules FROM vpn_permission WHERE user_name = "%s"' % (client_name)
    allow_rules = operating_db (sql)[0]['vpn_allow_rules']
    if allow_rules == '' or allow_rules == 'Null':
        sys.stderr.write("User can't access any ip.\n")
    elif allow_rules == '*':
        build_rule (client_ip,client_ip,"")
    else:
        allow_rules = allow_rules.split(',')
        for dst_ip in allow_rules:
            build_rule (client_ip, client_ip, dst_ip) 

def chain_exists(chain):
    return iptables('-n -L %s' % (chain,), False)

def add_chain(client_ip, client_name):
    del_chain (client_ip)

    Chain_INPUT_NUM,Chain_FORWARD_NUM = get_curr_rule_num ()

    if chain_exists (client_ip):
        sys.stderr.write("Attempted to replace an existing chain, failing.\n")
        sys.stderr.write("\tclient_ip=%s, client_name=%s\n" % (client_ip, client_name) )
        return False
    iptables('-N %s' % (client_ip,))
    iptables('-A OUTPUT  -d %s -j %s' % (client_ip,client_ip), False)

    if Chain_INPUT_NUM != 'Null':
        iptables('-I INPUT %s -s %s -j %s' % (Chain_INPUT_NUM, client_ip, client_ip), False)
    else:
        iptables('-A INPUT   -s %s -j %s' % (client_ip, client_ip), False)
    if Chain_FORWARD_NUM != 'Null':
        iptables('-I FORWARD %s -s %s -j %s' % (Chain_FORWARD_NUM, client_ip, client_ip), False)
        iptables('-I FORWARD %s -d %s -j %s' % (Chain_FORWARD_NUM, client_ip, client_ip), False)
    else:
        iptables('-A FORWARD -s %s -j %s' % (client_ip, client_ip), False)
        iptables('-A FORWARD -d %s -j %s' % (client_ip, client_ip), False)

    comment = client_name + ': '
    if len(comment) > 254:
        comment = comment[:243] + '..truncated...'

    load_rules (client_ip, client_name)

    iptables('-A %s -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "%s at %s"' % (client_ip, client_name, client_ip))
    iptables('-A %s -j LOG --log-prefix "DROP %s " -m comment --comment "%s at %s"' % (client_ip, client_name[:23], client_name, client_ip))
    iptables('-A %s -j DROP -m comment --comment "%s at %s"' % (client_ip, client_name, client_ip))
    return True

def del_chain(client_ip, client_name=None):
    iptables ('-D OUTPUT  -d %s -j %s >/dev/null 2>&1' % (client_ip, client_ip), False)
    iptables ('-D INPUT   -s %s -j %s >/dev/null 2>&1' % (client_ip, client_ip), False)
    iptables ('-D FORWARD -s %s -j %s >/dev/null 2>&1' % (client_ip, client_ip), False)
    iptables ('-D FORWARD -d %s -j %s >/dev/null 2>&1' % (client_ip, client_ip), False)
    iptables ('-F %s >/dev/null 2>&1' % (client_ip,), False)
    iptables ('-X %s >/dev/null 2>&1' % (client_ip,), False)
    return True

def update_chain(client_ip, client_name):
    return add_chain(client_ip, client_name)

def main():
    if len(sys.argv) < 2:
        print "USAGE: %s <operation>" % sys.argv[0]3.线上:10.58.25.121
        return False
    operation     = sys.argv[1]
    client_ip     = sys.argv[2]
    client_name   = sys.argv[3] if operation != 'delete' else 'none'

    sys.stderr.write ("vpn client: [%s] [%s]\n" % (operation, client_ip))

    chain_func = {
        'add':    add_chain,
        'update': update_chain,
        'delete': del_chain
    }
    try:
        chain_func[operation](client_ip, client_name)
        sys.exit(0)
    except Exception, e:
        sys.stderr.write("Bad operation! %s\n" % (e,))
    sys.exit(1)

def write_auth_control_file(control_status):
    auth_control_file = os.environ.get('auth_control_file', None)
    if auth_control_file:
        f = open(auth_control_file, 'w')
        f.write(control_status)
        f.close()

if __name__ == "__main__":
    main()
