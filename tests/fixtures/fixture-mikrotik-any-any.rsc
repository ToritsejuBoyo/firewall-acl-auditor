# Synthetic MikroTik RouterOS Configuration Export
# For automated testing of firewall-acl-auditor
# Device: SYNTHETIC-MOCK-MIKROTIK-01
/ip firewall filter
add chain=forward action=accept src-address=192.0.2.0/24 dst-address=0.0.0.0/0 comment="SYNTHETIC-PERMIT-BRANCH"
add chain=forward action=drop protocol=tcp src-address=192.0.2.192/26 dst-address=0.0.0.0/0 dst-port=443 comment="SYNTHETIC-DROP-SUBRANGE"
add chain=forward action=accept protocol=tcp src-address=192.0.2.0/24 dst-address=0.0.0.0/0 dst-port=80 comment="SYNTHETIC-REDUNDANT-HTTP"
add chain=forward action=accept protocol=tcp src-address=0.0.0.0/0 dst-port=23 comment="SYNTHETIC-INSECURE-TELNET"
add chain=forward action=accept src-address=0.0.0.0/0 dst-address=0.0.0.0/0 comment="SYNTHETIC-OVERLY-PERMISSIVE"
add chain=forward action=drop src-address=203.0.113.100 dst-address=0.0.0.0/0 disabled=yes comment="SYNTHETIC-ZOMBIE-DROP"
