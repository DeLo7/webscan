from PyQt5 import QtCore
from PyQt5.QtCore import pyqtSignal

from Web_scan.dlsql import sql_main


# 定义特点输入框的传值
def sql_get_input(main_window):
    url = main_window.sql_url.text()
    data = main_window.sql_data.text()
    proxy = main_window.sql_proxy.text()
    cookie = main_window.sql_cookie.text()
    ua = main_window.sql_user_agent.text()
    referer = main_window.sql_referer.text()
    # 如果存在必输项url则启动多线程
    if url:
        # init_options()
        main_window.start_sql_thread(url, data=data, proxy=proxy, cookie=cookie, ua=ua, referer=referer)


class SqlThread(QtCore.QThread):
    #  通过类成员对象定义信号对象
    res_signal = pyqtSignal(str)  # 主次线程联系标志变量
    end_signal = pyqtSignal(bool)

    def __init__(self, url, **kwargs):
        super(SqlThread, self).__init__()  # super继承父类方法（代表QThread类中的init)
        self.url = url
        self.options = kwargs

    def __del__(self):
        self.wait()

    def run(self):
        self.end_signal.emit(False)
        sql_main(self.url if self.url.startswith("http") else "http://%s" % self.url, self.res_signal, **self.options)
        self.end_signal.emit(True)
