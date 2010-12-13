import re

NULL = "NULL"


def _str_to_hex(s):
    if s:
        return "0x%s" % (s.encode("hex"))
    else:
        return NULL

class Sql:
    def __str__(self): abstract
    class InvalidSqlSyntax(Exception): pass
    
class Query(Sql):
    pass

class SqlFunction(Sql):
    name = None
    def __init__(self, expressions=None):
        self.expressions = expressions or []
    def __str__(self):
        if type(self.expressions) == list:
            return "%s(%s)" % (self.name, ",".join(map(str, self.expressions)))
        else:
            return "%s(%s)" % (self.name, self.expressions)


class CurrentDatabase(SqlFunction):
    name = "database"

class Concat(SqlFunction):
    name = "CONCAT"
    
class Binary(SqlFunction):
    name = "BINARY"

class Count(SqlFunction):
    name = "COUNT"

class Loadfile(Sql):
    def __init__(self, filename):
        self.filename = filename
    def __str__(self):
        return "load_file(%s)" % String(self.filename)

class String(Sql):
    def __init__(self, string):
        self.string = string
    def __str__(self):
        return _str_to_hex(self.string)

class Select(Query):
    def __init__(self, select_expressions, table_reference=None,
                 options=None, where_condition=None,
                 order_by=None, limit=None, outfile=None):
        self.select_expressions = select_expressions
        self.table_reference = table_reference
        self.options = options or []
        self.where_condition = where_condition
        self.order_by = order_by
        self.limit = limit
        self.outfile = outfile

    def copy(self):
        return Select(self.select_expressions, self.table_reference,
                      self.options, self.where_condition,
                      self.order_by, self.limit, self.outfile)

    def __str__(self):
        q = "SELECT"
        if self.options:
            q += " %s" % self.options
        q += " %s" % (",".join(map(str, self.select_expressions)))
        if self.table_reference:
            q += " FROM %s" % self.table_reference
        if self.where_condition:
            q += " WHERE %s" % self.where_condition
        if self.order_by:
            q += " ORDER BY %s" % self.order_by
        if self.limit:
            q += " LIMIT %s" % (",".join(self.limit))
        if self.outfile:
            q += " INTO OUTFILE %s" % (self.outfile)
        return self.convert_strings(q)

    def convert_strings(self, s):
        def _repl(m):
            return _str_to_hex(m.group(1))
        return re.sub('"(.*?)"', _repl, s)
        

    @classmethod
    def parse(self, args):
        def _split_comas(expressions):
            if expressions:
                return map(lambda s: s.strip(), expressions.split(","))
        r = re.compile("^\s*(?P<options>((distinct|binary)\s+)*)\s*" + \
                       "(?P<select_expressions>\S.*?)\s*" +\
                       "(FROM\s+(?P<table_reference>.*?))?\s*" + \
                       "(WHERE\s+(?P<where_condition>.*?))?\s*" + \
                       "(ORDER\s+BY\s+(?P<order_by>.*?))?\s*" + \
                       "(LIMIT\s+(?P<limit>.*?))?\s*" + \
                       "(INTO OUTFILE\s+(?P<outfile>.*?))?\s*" + \
                       "$", re.I)
        m = r.match(str(args))
        if not m:
            raise self.InvalidSqlSyntax
        data = m.groupdict()
        data['select_expressions'] = _split_comas(data['select_expressions'])
        data['limit'] = _split_comas(data['limit'])
        return Select(**data)
