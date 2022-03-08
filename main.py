# -*- coding: utf-8 -*-
import sys
from PyQt5 import QtWidgets
from Ui.ui_main import UiMainWindow
from thread_part.sql_ui_method import sql_get_input
from thread_part.xss_ui_method import xss_get_input
from thread_part.js_ui_method import js_get_input

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    main_window = UiMainWindow()  # 创建UI视图对象
    main_window.show()  # 视图对象UI展示

    main_window.sql_start_button.clicked.connect(lambda: sql_get_input(main_window))  # SQL模块开始按钮绑定事件
    main_window.xss_start_button.clicked.connect(lambda: xss_get_input(main_window))  # XSS模块开始按钮绑定事件
    main_window.js_start_button.clicked.connect(lambda: js_get_input(main_window))  # JS模块开始按钮绑定事件
    sys.exit(app.exec_())
