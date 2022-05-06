# Python 3 required
import difflib  # 序列的差异化比较
import http.client
import itertools  # 创建和使用迭代器
import optparse
import random
import re
import urllib
import urllib.parse
import urllib.request
from PyQt5.QtCore import pyqtSignal

NAME, VERSION, AUTHOR = "Small SQLi Scanner (DLSQL)", "1.0", "delo"
# 用于构建测试盲注有效载荷的前缀值
PREFIXES = (" ", ") ", "' ", "') ", "\" ", "\") ")
# 用于构建测试盲注有效载荷的后缀值
SUFFIXES = ("", "-- -", "#", "--+")
# 用于 SQL 篡改参数值中毒的字符,匹配特殊字符
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"')
# 用于构建测试盲有效载荷的布尔测试
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d>%d)")
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"
GET, POST = "GET", "POST"
TEXT, HTTPCODE, TITLE, HTML = range(4)
# 范围 (0,1) 中的比率值，用于区分 True 和 False 响应
FUZZY_THRESHOLD = 0.95
TIMEOUT = 30
RANDINT = random.randint(1, 255)
# 用于识别通用防火墙阻止消息的正则表达式：可定制国内的防火墙关键字
BLOCKED_IP_REGEX = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)"

# 用于基于错误消息响应的 DBMS 识别的正则表达式
DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (
        r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (
        r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
               r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}


# 请求指定url并提取页面内容
def _retrieve_content(url, data=None):
    retval = {HTTPCODE: http.client.OK}
    # print(retval)
    try:
        # 构造请求包
        req = urllib.request.Request(
            # 生成器：从右往左开始读， 查找第一个?出现的位置并返回索引值，然后判断?号后面的字符串是否存在空格，空格就替换成%20
            "".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_] for _ in range(len(url))),
            # data必须是bytes(字节流）类型，如果是字典，可以用urllib.parse模块里的urlencode()编码，'ignore' 忽略无法编码的字符
            data.encode("utf8", "ignore") if data else None,
            # 判断是否存在_header字典，不存在返回空{}
            globals().get("_headers", {}))
        # 请求读取目标url内容
        retval[HTML] = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception as ex:
        #  获取失败的Response code
        retval[HTTPCODE] = getattr(ex, "code", None)
        # 尝试获取请求失败的页面源码,否则获取报错信息
        retval[HTML] = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
    retval[HTML] = (retval[HTML].decode("utf8", "ignore") if hasattr(retval[HTML], "decode") else "") or ""
    # 寻找retval[HTML]对象中是否存在防火墙关键字，若是则将retval[HTML]网页源码对象置空
    retval[HTML] = "" if re.search(BLOCKED_IP_REGEX, retval[HTML]) else retval[HTML]
    # print "替换前"
    # print retval[HTML]

    #  匹配and RANDINT ，其中and RANDINT中间不能有<号，如果匹配到则把匹配到的替换成__REFLECTED__
    retval[HTML] = re.sub(r"(?i)[^>]*(AND|OR)[^<]*%d[^<]*" % RANDINT, "__REFLECTED__", retval[HTML])
    # print '替换后'
    # print retval[HTML]

    # 查看页面源码中有无title标签：匹配标题,并且标题中不能出现<号
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    # 将大部分的标签替换成空格：将标签开头到标签结尾替换成空格,只留下文本,如 <script>123123</script> 456456,经过替换后,只剩下456456
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    # 最后返回retval赋值给original，最终包含这几个：HTML，TEXT，TITLE，HTTPCODE
    return retval


def scan_page(url, res_signal: pyqtSignal(str), data=None):
    # res_signal.emit("i‘m QThread")
    retval, usable = False, False
    # 寻找等号后面是&或结尾符的替换成=1 ，整句的目的是如果有未赋值的参数会给它默认赋值为1
    url = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url
    data = re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    # print(url)
    # print(data)
    try:
        for phase in (GET, POST):
            original, current = None, url if phase is GET else (data or "")
            # 将参数和参数值提取出来：大概的意思是匹配以?或&开头的，然后匹配parameter和value，其中parameter为不匹配以下划线_开头的字符串，其中字符串为[a-zA-Z0-9_],value为不包含&和#的字符串
            '''
            \A 表示仅匹配字符串开头
            (?P<parameter>) 以parameter作为别名进行分组
            \w 单词字符[a-zA-Z0-9_]
            '''
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", current):
                # print(match)
                vulnerable, usable = False, True
                if not res_signal:
                    print("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                else:
                    res_signal.emit("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                # 如果是GET方式，就返回_retrieve_content(current, data) ，而这里的current为url，data为None
                # 如果是POST方式：返回_retrieve_content(url, current) 这里的url是url，而current为POST_Body，也就是POST过来的数据。
                # 第一次请求：正常请求
                original = original or (
                    _retrieve_content(current, data) if phase is GET else _retrieve_content(url, current))
                # print(match.group(0))
                # print(original)

                ###### 报错注入测试 ######
                # 篡改url中的参数:给参数添加额外的随机值，url编码额外的随机值:id=1"()'
                tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote(
                    "".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL))))))
                # print(tampered)

                # 第二次请求：添加随机字符编码payload后的请求
                content = _retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)
                # 大概就是轮训每个value，将key对应轮训的value。
                for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                    # vulnerable默认为False ， 去寻找特殊字符请求的url content，regex出现在content中，还有regex没出现在正常请求的content中，那么就代表存在报错注入。
                    # 并设置retval和vulnerable为True，vulnerable为True以后不再进入这个if判断。
                    if not vulnerable and re.search(regex, content[HTML], re.I) and not re.search(regex, original[HTML],
                                                                                                  re.I):
                        if not res_signal:
                            print(" (i) %s parameter '%s' appears to be error SQLi vulnerable (%s)" % (
                                phase, match.group("parameter"), dbms))
                        else:
                            res_signal.emit(" (i) %s parameter '%s' appears to be error SQLi vulnerable (%s)" % (
                                phase, match.group("parameter"), dbms))
                        retval = vulnerable = True
                vulnerable = False
                ###### 布尔注入测试 ######
                # 生成payload，总的是6*2*4=48个组合,48*2=96
                for prefix, boolean, suffix, inline_comment in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES,
                                                                                 (False, True)):
                    if not vulnerable:
                        # 把inline_comment 为True的空格替换成/**/ ，也就是一半payload是空格，一半payload是/**/
                        template = ("%s%s%s" % (prefix, boolean, suffix)).replace(" " if inline_comment else "/**/",
                                                                                  "/**/")
                        # print "template:--------"
                        # print template
                        # print '-----------------'

                        # 给template 赋随机的数字然后url编码（对%不编码），接着再次分and 1=1 和and 1=2 然后添加到url参数中，
                        # 并标记False和True，到现在总的payload有96*2=192个
                        payloads = dict((_, current.replace(match.group(0), "%s%s" % (match.group(0),
                                                                                      urllib.parse.quote(template % (
                                                                                          RANDINT if _ else RANDINT + 1,
                                                                                          RANDINT), safe='%')))) for _
                                        in
                                        (True, False))
                        # 第三次请求
                        # 带着and 1=1 和 and 1=2 类似的payload去请求返回contents，其中and 1=1是contents[True]， and 1=2是contents[False]
                        contents = dict((_, _retrieve_content(payloads[_], data) if phase is GET else _retrieve_content(
                            url, payloads[_])) for _ in (False, True))

                        # 精准判断：用HTTPCODE或TITLE作为依据来判断
                        # 看三个content的返回状态值。如果三次请求中有个状态值大于500就返回False（http.client.INTERNAL_SERVER_ERROR = 500）
                        if all(_[HTTPCODE] and _[HTTPCODE] < http.client.INTERNAL_SERVER_ERROR for _ in
                               (original, contents[True], contents[False])):
                            if any(original[_] == contents[True][_] != contents[False][_] for _ in (HTTPCODE, TITLE)):
                                vulnerable = True

                            # 根据页面内容差异性进行模糊判断
                            # 如果通过上面对比状态码和标题返回是False的话，那么就对三个content进行对比，返回其相似程度。
                            else:
                                '''
                                1.两次中每次的相似度都不为0，
                                2.并且最小的相似度和最大的相似度要在0.95之间
                                3.还有就是两者的相似度之差要大于0.095
                                同时满足这三个条件也算是存在注入
                                '''
                                ratios = dict(
                                    (_, difflib.SequenceMatcher(None, original[TEXT], contents[_][TEXT]).quick_ratio())
                                    for _ in (False, True))
                                vulnerable = all(ratios.values()) and min(ratios.values()) < FUZZY_THRESHOLD < max(
                                    ratios.values()) and abs(ratios[True] - ratios[False]) > FUZZY_THRESHOLD / 10
                        if vulnerable:
                            if not res_signal:
                                print(" (i) %s parameter '%s' appears to be blind SQLi vulnerable (e.g.: '%s')" % (
                                    phase, match.group("parameter"), payloads[True]))
                            else:
                                res_signal.emit(
                                    " (i) %s parameter '%s' appears to be blind SQLi vulnerable (e.g.: '%s')" % (
                                        phase, match.group("parameter"), payloads[True]))
                            retval = True
        if not usable:
            if not res_signal:
                print(" (x) no usable GET/POST parameters found")
            else:
                res_signal.emit(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        if not res_signal:
            print("\r (x) Ctrl-C pressed")
        else:
            res_signal.emit("\r (x) Ctrl-C pressed")
    return retval


# 加载proxy(代理)，cookie，ua，referer
def init_options(proxy=None, cookie=None, ua=None, referer=None):
    # 判断元组（不可变性）中的_[1]中的值是否为false也就是null,若是则舍弃然后组成全局字典_headers
    globals()["_headers"] = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    # print (_headers)
    # urllib2.urlopen()函数不支持验证、cookie或者其它HTTP高级功能。要支持这些功能，必须使用build_opener()函数创建自定义Opener对象。
    urllib.request.install_opener(
        urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy})) if proxy else None)


def sql_main(url, res_signal: pyqtSignal(str), **kwargs):
    data = kwargs.get("data", None)
    ua = kwargs.get("ua", None)
    referer = kwargs.get("referer", None)
    proxy = kwargs.get("proxy", None)
    cookie = kwargs.get("cookie", None)

    init_options(proxy, cookie, ua, referer)
    result = scan_page(url if url.startswith("http") else "%http://s" % url, res_signal, data)
    print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    res_signal.emit("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    res_signal.emit('end of sql scan ! ')


if __name__ == "__main__":
    print("%s  #v%s  by: %s" % (NAME, VERSION, AUTHOR))
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    options, _ = parser.parse_args()
    if options.url:
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        # 传两个参数一个url，一个data
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, None,
                           options.data)
        print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    else:
        parser.print_help()

'''
大概思路:基于报错注入和布尔盲注
(1)程序运行开始，可能传进来的值总结来说有4个：url，header ，post_data ， proxy
(2)然后对其进行参数分割，分两块：
    1.get的参数分割
    2.post_data的参数分割。
    分割完如果没有值的参数补上参数值等于1，然后第一次去请求，记录下请求的content值，title值，状态码， content的过滤值(这里指过滤<>里面的值)每次的请求都会记录下这四个值，
(3)报错注入：这时候会对参数添加 （）"' 这四个字符串随机组合，如果返回的页面有存在 DBMS_ERRORS ，那么就存在报错注入
(4)布尔盲注：
接着就开始生成payload，大概有32个payload,但是不需要都跑完，跑到一次正确的后面的就不用在跑了。
    这里payload又分为两种：
    1.存在空格的payload
    2.将空格替换成/**/的payload
    这时候要请求的payload又变成了64个。
    然后请求的时候对 and 1=1 and 1=2 各检测一次来对比，请求有三个。
    1.第一次正常的请求
    2.请求参数加and 1=1 注：num都是随机数
    3.请求参数加and 1=2
(5) 
    精准判断：
    1.通过请求这三次的TITLE值来对比， 第一个和第二个相同，第二个和第三个的TITLE值不相同，就判断为注入。
    2.通过请求这三次的HTTPCODE值来对比，第一个和第二个相同，第二个和第三个的HTTPCODE值不相同，就判断为注入。
    模糊判断：
    3.如果上面两种方式没通过，通过请求这三次的content的过滤值来对比：
        1.两次中每次的相似度都不为0，
        2.并且最小的相似度和最大的相似度要在0.95之间，
        3.还有就是两者的相似度之差要大于0.095 。

上面三种方式有一个通过就算注入。
'''
