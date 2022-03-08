# Python 3 required
import distutils.version
import glob
import hashlib
import json
import optparse
import os
import re
import ssl
import tempfile
import urllib
import urllib.parse
import urllib.request
from PyQt5.QtCore import pyqtSignal

NAME, VERSION, AUTHOR, COMMENT = "Small SQLi Scanner (DLSQL)", "1.0", "delo", "(https://bekk.github.io/retire.js/)"
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"  # optional HTTP header names
TIMEOUT = 30  # connection timeout in seconds
RETIRE_JS_DEFINITIONS = "https://raw.githubusercontent.com/retirejs/retire.js/master/repository/jsrepository.json"  # Retire.JS definitions
# 定义中的 Retire.JS 版本标记
RETIRE_JS_VERSION_MARKER = u"(\xa7\xa7version\xa7\xa7)"  # Retire.JS version marker inside definitions

# 忽略过期和/或自签名证书
ssl._create_default_https_context = ssl._create_unverified_context  # ignore expired and/or self-signed certificates
_headers = {}  # used for storing dictionary with optional header values

# 请求页面
def _retrieve_content(url, data=None):
    try:
        req = urllib.request.Request(
            "".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in range(len(url))),
            data.encode("utf8", "ignore") if data else None, _headers)
        retval = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception as ex:
        retval = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
    return (retval.decode("utf8", "ignore") if hasattr(retval, "decode") else "") or ""

# 查看读取js漏洞字典文件
def _get_definitions():
    # tempfile.gettempdir()获取系统的临时目录。
    # os.path.join() 函数用于路径拼接文件路径
    #  glob.glob()查找符合特定规则的文件路径名。跟使用windows下的文件搜索差不多
    search = glob.glob(os.path.join(tempfile.gettempdir(), "retire*.json"))
    if search:
        # 先查看本地是否有retire*.json的字典文件
        content = open(search[0], "r").read()
    else:
        # 若本地不存在retire*.json类型的字典文件则请求远程的json字典文件
        content = _retrieve_content(RETIRE_JS_DEFINITIONS)
        if not content:
            print("[x]")
            exit(-1)
        # 创建临时文件，tempfile.mkstemp返回值是一对(fd, name)，其中fd是os.open返回的文件描述符，name是文件名。
        handle, _ = tempfile.mkstemp(prefix="retire", suffix=".json", dir=tempfile.gettempdir())
        # 将远程请求的json字典文件写入本地保存
        os.write(handle, content.encode("utf8"))
        os.close(handle)
    # json.loads(content)，解码 JSON 数据。该函数返回 Python 字段的数据类型
    return json.loads(content)


def scan_page(url, res_signal: pyqtSignal(str)):
    retval = False
    try:
        hashes = dict()
        scripts = dict()
        content = _retrieve_content(url)
        # 页面中找js脚本路径
        for match in re.finditer(r"<script[^>]+src=['\"]?([^>]+.js)\b", content):
            # 组成绝对路径=url+js的相对路径
            script = urllib.parse.urljoin(url, match.group(1))
            if script not in scripts:
                _ = _retrieve_content(script)
                if _:
                    scripts[script] = _ # script是url，_是请求的回显内容
                    # hashlib.sha1(_.encode("utf8")).hexdigest()是一个hash加密
                    hashes[hashlib.sha1(_.encode("utf8")).hexdigest()] = script
        if scripts:
            # 得到js漏洞字典
            definitions = _get_definitions()
            # 不检查js的url黑名单
            for _ in definitions["dont check"]["extractors"]["uri"]:
                for script in dict(scripts):
                    # 如果存在黑名单里的url则删除scripts字典中的它
                    if re.search(_, script):
                        del scripts[script]
            # items()以列表返回可遍历的(键, 值) 元组数组：字典变成元组(键, 值)组成的列表
            for library, definition in definitions.items():
                version = None
                for item in definition["extractors"].get("hashes", {}).items():
                    if item[0] in hashes:
                        version = item[1]
                for part in ("filename", "uri"):
                    for regex in (_.replace(RETIRE_JS_VERSION_MARKER, "(?P<version>[^\s\"]+)") for _ in
                                  definition["extractors"].get(part, [])):
                        for script in scripts:
                            match = re.search(regex, script)
                            version = match.group("version") if match else version
                for script, content in scripts.items():
                    for regex in (_.replace(RETIRE_JS_VERSION_MARKER, "(?P<version>[^\s\"]+)") for _ in
                                  definition["extractors"].get("filecontent", [])):
                        match = re.search(regex, content)
                        version = match.group("version") if match else version
                if version and version != "-":
                    for vulnerability in definition["vulnerabilities"]:
                        _ = vulnerability.get("atOrAbove", 0)
                        if distutils.version.LooseVersion(str(_)) <= version < distutils.version.LooseVersion(
                                vulnerability["below"]):
                            if not res_signal:
                                print(" [x] %s %sv%s (< v%s) (info: '%s')" % (
                                    library, ("" if not _ else "(v%s <) " % _), version.replace(".min", ""),
                                    vulnerability["below"], "; ".join(vulnerability["info"])))
                            else:
                                res_signal.emit(" [x] %s %sv%s (< v%s) (info: '%s')" % (
                                    library, ("" if not _ else "(v%s <) " % _), version.replace(".min", ""),
                                    vulnerability["below"], "; ".join(vulnerability["info"])))
                            retval = True
    except KeyboardInterrupt:
        if not res_signal:
            print("\r (x) Ctrl-C pressed")
        else:
            res_signal.emit("\r (x) Ctrl-C pressed")
    except Exception as e:
        if not res_signal:
            print(e.args)
        else:
            res_signal.emit(e.args)

    return retval


def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global _headers
    _headers = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    urllib.request.install_opener(
        urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy})) if proxy else None)


def js_main(url, res_signal: pyqtSignal(str), **kwargs):
    # data = kwargs.get("data", None)
    # res_signal.emit('123')
    ua = kwargs.get("ua", None)
    referer = kwargs.get("referer", None)
    proxy = kwargs.get("proxy", None)
    cookie = kwargs.get("cookie", None)

    init_options(proxy, cookie, ua, referer)
    result = scan_page(url if url.startswith("http") else "http://%s" % url, res_signal)
    print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    res_signal.emit("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    res_signal.emit('end of js scan ! ')


if __name__ == "__main__":
    print("%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR))
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    options, _ = parser.parse_args()
    if options.url:
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, None)
        print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    else:
        parser.print_help()
