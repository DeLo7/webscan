# Python 3 required
# 1><img/src=x onerror=prompt(/xss/)><
import optparse
import random
import re
import string
import urllib
import urllib.parse
import urllib.request
from PyQt5.QtCore import pyqtSignal

NAME, VERSION, AUTHOR = "Small Xss Scanner (DLXSS)", "1.0", "delo"
# 用于 XSS 篡改参数值的字符（较小的集合 - 用于避免可能的 SQLi 错误）
SMALLER_CHAR_POOL = ('<', '>')
# 用于 XSS 篡改参数值的字符（更大的集合）
LARGER_CHAR_POOL = ('\'', '"', '>', '<', ';')
# 提交类型
GET, POST = "GET", "POST"
# XSS 篡改中使用的随机前缀后缀长度
PREFIX_SUFFIX_LENGTH = 5
# 可选的 HTTP 标头名称
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"
# 连接超时（以秒为单位）
TIMEOUT = 30
# 在 DOM XSS 搜索之前使用的过滤正则表达式
'''
. 匹配除换行符（\n、\r）之外的任何单个字符
* 是取 0 至 无限长度
? 是非贪婪模式。? 问号代表前面的字符最多只可以出现一次
<.*?> 加上？为将贪婪匹配模式转为非贪婪匹配模式，会匹配尽量短的字符串
+ 号代表前面的字符必须至少出现一次
\b 匹配一个单词边界，即字与空格间的位置
\B 非单词边界匹配。
'''
# 匹配单双引号内的内容，escape()函数：js中的编码函数,注释等
DOM_FILTER_REGEX = r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"

# 每个元组都代表输出点在dom结点中的一个确定的位置，比如：script标签内、单引号内、注释内
# 匹配有可能存在xss的字符串的正则，攻击成功需要哪些字符未经过滤，说明(简易表达匹配格式)，获取响应包后首先筛掉的字符的regexp
# 每个（常规模式）项目由 (r"context regex", (prerequisite unfiltered characters), "info text", r"content removal regex")
REGULAR_PATTERNS = (
    # <> 不被过滤 纯字符
    (r"\A[^<>]*%(chars)s[^<>]*\Z", ('<', '>'), "\".xss.\", pure text response, %(filtering)s filtering", None),
    # <> 不被过滤 是在注释内
    (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->", ('<', '>'),
     "\"<!--.'.xss.'.-->\", inside the comment, %(filtering)s filtering", None),
    # ' ; 不被过滤 在<script> 标签内被单引号包裹 使用方式: 先闭合单引号然后 ;终端语句再自定义js
    (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'),
     "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering",
     r"\\'|{[^\n]+}"),
    # 这个被双引号包裹的 其他同上
    (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'),
     "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering",
     r'\\"|{[^\n]+}'),
    # ; 不被过滤 在script标签内 没有单双引号包裹 直接分号中断
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',),
     "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering",
     r"&(#\d+|[a-z]+);|'[^'\s]+'|\"[^\"\s]+\"|{[^\n]+}"),
    # <> 不被过滤在标签外的 自己使用标签 每次匹配后要删除对于的一些东西比如这里 删除script标签和注释 防止xss匹配重合
    (r">[^<]*%(chars)s[^<]*(<|\Z)", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->"),
    # ' 单引号不被过滤 在标签内 被单引号包裹
    (r"<[^>]*=\s*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',),
     "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    # " 双引号 同上
    (r'<[^>]*=\s*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',),
     "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    # 标签内，引号外 <img xss>等
    (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->|=\s*'[^']*'|=\s*\"[^\"]*\""),
)
# 每个（dom 模式）项目由 r"recognition regex" 组成
DOM_PATTERNS = (
    r"(?s)<script[^>]*>[^<]*?(var|\n)\s*(\w+)\s*=[^;]*(document\.(location|URL|documentURI)|location\.("
    r"href|search)|window\.location)[^;]*;[^<]*(document\.write(ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\("
    r"|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*\2.*?</script>",
    r"(?s)<script[^>]*>[^<]*?(document\.write\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.("
    r"replace|assign)\(|setAttribute\()[^;]*(document\.(location|URL|documentURI)|location\.("
    r"href|search)|window\.location).*?</script>",
)

# 用于存储带有可选标头值的字典
_headers = {}


# 抓包返回结果的包装函数
def _retrieve_content(url, data=None):
    try:
        # 构造请求包
        req = urllib.request.Request(
            # 生成器：从右往左开始读， 查找第一个?出现的位置并返回索引值，然后判断?号后面的字符串是否存在空格，空格就替换成%20
            "".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in range(len(url))),
            # data必须是bytes(字节流）类型，如果是字典，可以用urllib.parse模块里的urlencode()编码，'ignore' 忽略无法编码的字符
            data.encode("utf8", "ignore") if data else None, _headers)
        # 请求包请求并读取目标回显内容
        retval = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception as ex:
        # hasattr()判断对象是否包含对应的属性。如果对象有该属性返回 True，否则返回 False。
        retval = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
        # 判断retval对象是否包含decode属性，若包含则utf-8解码，否则置为空
    return (retval.decode("utf8", "ignore") if hasattr(retval, "decode") else "") or ""


# 返回一个布尔值，保证content中包含所有chars中的元素，且确保chars的每个元素中至少有一个没有被转义（前面未加反斜杠）
# 确定“必备未过滤的字符”是否有被过滤 原理是判断是否在字符前面存在\
def _contains(content, chars):
    # 去掉content中包含的被转义的chars
    # print(content)
    # print(chars)
    content = re.sub(r"\\[%s]" % re.escape("".join(chars)), "", content) if chars else content
    # 在上一步去掉被转义的字符后，这里保证content中仍然包含chars中的所有元素
    return all(char in content for char in chars)


def scan_page(url, res_signal: pyqtSignal(str), data=None):
    # res_signal.emit("i‘m QThread")
    retval, usable = False, False
    # 对未传入参数值的参数进行赋1操作
    url = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url
    data = re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    '''Dom型XSS检测'''
    # 先用_retrieve_content 请求url然后交与正则DOM_FILTER_REGEX
    # r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"
    # 首先根据dom_filter_regex去掉响应包中的内容（用于清除多余字符串如：单双引号内的内容，escape()函数,注释等）
    original = re.sub(DOM_FILTER_REGEX, "", _retrieve_content(url, data)) # original的值就是排除干扰和外加因素后的网页回显内容
    # DOM_PATTERNS 从响应体中正则判断是否存在 dom xss 可能性及在响应中查找dom_patterns（容易造成漏洞的功能函数或特殊函数），如果存在，则提示可能存在dom-xss
    # 因为dom型xss是js直接操作节点造成的所以js源码有能正则匹配的document\.write\(|\.innerHTML location setTimeout等
    # next() 返回迭代器的下一个项目。用于设置在没有下一个元素时返回该默认值，如果不设置，又没有下一个元素则会触发 StopIteration 异常
    dom = next(filter(None, (re.search(_, original) for _ in DOM_PATTERNS)), None)
    # 如果匹配到了可能存在dom xss 并输出匹配的地方
    if dom:
        if not res_signal:
            print(" (i) page itself appears to be XSS vulnerable (DOM)")
            # group(0)匹配的正则表达式整体结果
            print("  (o) ...%s..." % dom.group(0))
        else:
            res_signal.emit(" (i) page itself appears to be XSS vulnerable (DOM)")
            res_signal.emit("  (o) ...%s..." % dom.group(0))
        # 设置结果存在
        retval = True
    '''参数型XSS检测'''
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            # get的话 current就是url
            # 解析url的parameter 参数
            # 将参数和参数值提取出来：大概的意思是匹配以?或&开头的，然后匹配parameter和value，其中parameter为不匹配以下划线_开头的字符串，其中字符串为[a-zA-Z0-9_],value为不包含&和#的字符串
            '''
            \A 输入（input）的开始位置（表示仅匹配字符串开头）
            (?P<parameter>) 以parameter作为别名进行分组
            [^_] 意思是匹配任何字符除了下划线
            \w 单词字符[a-zA-Z0-9_]
            * 匹配0次或无数次
            '''
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):
                # found为true时代表找到存在漏洞的参数；usable为true代表url或post-data中存在键值对
                found, usable = False, True
                if not res_signal:
                    print("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                else:
                    res_signal.emit("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                # 赋值两个长度为5的随机字符的字符串列表：prefix和suffix两个分别作为前后缀
                prefix, suffix = ("".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH)) for i in
                                  range(2))
                # print(prefix)
                # print(suffix)
                # SMALLER_CHAR_POOL    = ('<', '>')
                # LARGER_CHAR_POOL     = ('\'', '"', '>', '<', ';')
                # 然后使用一个for循环，针对larger_char_pool和smaller_char_pool进行单独的测试.之所以要用两个list的原因是防止后端使用
                # waf/ids时对payload进行拦截，所以使用了一个smaller_payload来避免过于明显的payload[即有较少的特殊字符]）也防止sql注入误报 。
                for pool in (LARGER_CHAR_POOL, SMALLER_CHAR_POOL):
                    # found默认就是False
                    if not found:
                        # 将参数改为 参数加 前缀+LARGER_CHAR_POOL+后缀 就是判断 <> 是否过滤
                        # payload格式为prefix+larger_pool中所有字符的随机排序+suffix
                        # 例：1'hjref>;'"<zyftg
                        tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote(
                            "%s%s%s%s" % (
                                # 加一个‘的原因：
                                # 1) .试图触发xss
                                # 2) .故意构造一个错误的sql语句用于报错，试图在报错信息中寻找触发点
                                "'" if pool == LARGER_CHAR_POOL else "", prefix,
                                "".join(random.sample(pool, len(pool))),
                                suffix))))
                        # 替换后的新的url
                        # 发起请求获取响应体 content
                        content = (_retrieve_content(tampered, data) if phase is GET else _retrieve_content(url,
                                                                                                            tampered)).replace(
                            "%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix), prefix)  # replace的作用是将回显内容中的单引号去掉，防止干扰后面的判断
                        # 查找之前传入的随机字符串匹配看是否被过滤 <> 找到后输出 并清除匹配的相关字符串
                        # 只是根据位置来判断 输出利用方式
                        for regex, condition, info, content_removal_regex in REGULAR_PATTERNS:
                            # 替换返回包中的需要去除的内容防止误判及清除匹配的相关字符串
                            filtered = re.sub(content_removal_regex or "", "", content)
                            # 用给定的正则匹配方式去匹配文本中存在的prefix和suffix看看是否插入成功去定位插入数据在文本中的位置
                            for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), filtered, re.I):
                                # re.escape自动给特殊符号添加转义\
                                # 根据上一步定位到的插入数据的位置去判断插入数据前后字符，标单控件等，去判断它符合上面9种的情况的哪一种情况
                                context = re.search(regex % {"chars": re.escape(sample.group(0))}, filtered, re.I)

                                if context and not found and sample.group(1).strip():
                                    # 是否有指定关键词被转义，若无就返回结果
                                    if _contains(sample.group(1), condition):
                                        if not res_signal:
                                            print(" (i) %s parameter '%s' appears to be XSS vulnerable (%s)" % (
                                                phase, match.group("parameter"), info % dict((("filtering", "no" if all(
                                                    char in sample.group(1) for char in
                                                    LARGER_CHAR_POOL) else "some"),))))
                                        else:
                                            res_signal.emit(
                                                " (i) %s parameter '%s' appears to be XSS vulnerable (%s)" % (
                                                    phase, match.group("parameter"),
                                                    info % dict((("filtering", "no" if all(
                                                        char in sample.group(1) for char in
                                                        LARGER_CHAR_POOL) else "some"),))))

                                        found = retval = True
                                    break
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


# 获取我们传入的参数当作全局变量存储：加载proxy(代理)，cookie，ua，referer
def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global _headers
    # 判断元组（不可变性）中的_[1]中的值是否为false也就是null,若是则舍弃然后组成全局字典_headers
    _headers = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    # print (_headers)
    # urllib2.urlopen()函数不支持验证、cookie或者其它HTTP高级功能。要支持这些功能，必须使用build_opener()函数创建自定义Opener对象。
    urllib.request.install_opener(
        urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy})) if proxy else None)


def xss_main(url, res_signal: pyqtSignal(str), **kwargs):
    data = kwargs.get("data", None)
    ua = kwargs.get("ua", None)
    referer = kwargs.get("referer", None)
    proxy = kwargs.get("proxy", None)
    cookie = kwargs.get("cookie", None)

    init_options(proxy, cookie, ua, referer)
    result = scan_page(url if url.startswith("http") else "http://%s" % url, res_signal, data)
    print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    res_signal.emit("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    res_signal.emit('end of xss scan ! ')


if __name__ == "__main__":
    print("%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR))
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
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, None,
                           options.data)
        print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    else:
        parser.print_help()
'''
支持dom型，存储型，反射性XSS检测
思路原理：
1. 先检测dom型xss：
    首先根据DOM_FILTER_REGEX去掉响应包中可能会影响检测的内容（如注释，文本内容等）只保留js的基础利用框架，然后在响应中查找dom_patterns（一些容易引起漏洞的功能函数或者特殊函数），如果存在，并且匹配其参数是否可控。则提示可能存在dom-xss
2. 再检测其他xss漏洞：
    这里先是通过正则判断输出点在dom树中的位置，然后确定如果想要触发xss需要哪些字符不被过滤，接着再根据响应包中的payload中的特殊字符前是否有反斜杠来确定其是否被过滤从而确定是否满足上面的条件，满足则存在漏洞。
'''
