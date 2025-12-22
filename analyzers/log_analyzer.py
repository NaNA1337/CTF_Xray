#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
日志分析模块
用于分析Web/系统日志，查找可能包含flag的内容
"""

import re
from PySide6.QtCore import QObject, Signal, QThread
import base64
import binascii
import json


class LogAnalyzerWorker(QObject):
    """日志分析工作线程"""
    finished = Signal(list)  # 发送分析结果
    error = Signal(str)      # 发送错误信息
    
    def __init__(self, log_file):
        super().__init__()
        self.log_file = log_file
        self.analysis_process = []  # 存储分析过程
        
    def run(self):
        """执行分析任务"""
        try:
            print("=" * 50)
            print(f"开始分析日志文件: {self.log_file}")
            print("=" * 50)
            
            results = self.analyze_logs()
            # 将分析过程添加到结果中
            results.append({"type": "ANALYSIS_PROCESS", "content": json.dumps(self.analysis_process, ensure_ascii=False)})
            
            print("=" * 50)
            print(f"日志分析完成，共发现{len(results)-1}条记录")  # -1是因为包含了ANALYSIS_PROCESS
            print("=" * 50)
            
            self.finished.emit(results)
        except Exception as e:
            print("=" * 50)
            print(f"日志分析出错: {str(e)}")
            print("=" * 50)
            self.error.emit(str(e))
    
    def analyze_logs(self):
        """
        分析日志文件
        返回包含发现的flag相关数据的列表
        """
        results = []
        
        # 记录分析步骤
        self.analysis_process.append({"step": "开始分析", "details": f"开始分析日志文件: {self.log_file}"})
        
        # 定义flag模式
        flag_patterns = [
            r'(flag|FLAG|CTF|ctf)\{[^}]*\}',  # flag{...} 或 CTF{...}
            r'(flag|FLAG|CTF|ctf)\([^)]*\)',  # flag(...) 或 CTF(...)
            r'(flag|FLAG|CTF|ctf)\[[^\]]*\]', # flag[...] 或 CTF[...]
        ]
        
        line_number = 0
        
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_number += 1
                    line = line.strip()
                    
                    # 记录进度（每1000行记录一次）
                    if line_number % 1000 == 0:
                        self.analysis_process.append({"step": "分析进度", "details": f"已分析{line_number}行"})
                        print(f"日志分析进度: 已分析{line_number}行")
                    
                    # 检查是否有直接的flag模式匹配
                    for pattern in flag_patterns:
                        matches = re.findall(pattern, line, re.IGNORECASE)
                        for match in matches:
                            result_entry = {
                                "line_number": line_number,
                                "content": line[:100] + "..." if len(line) > 100 else line,
                                "match": str(match)
                            }
                            results.append(result_entry)
                            
                            print(f"在第{line_number}行发现匹配: {match}")
                    
                    # 检查base64编码的内容
                    b64_matches = self.find_base64_in_line(line)
                    for match in b64_matches:
                        decoded = self.try_decode_base64(match)
                        if decoded and self.contains_flag_pattern(decoded):
                            result_entry = {
                                "line_number": line_number,
                                "content": line[:100] + "..." if len(line) > 100 else line,
                                "match": f"Base64: {match} -> {decoded}"
                            }
                            results.append(result_entry)
                            
                            print(f"在第{line_number}行发现Base64编码的FLAG: {match} -> {decoded}")
                    
                    # 检查十六进制编码的内容
                    hex_matches = self.find_hex_in_line(line)
                    for match in hex_matches:
                        decoded = self.try_decode_hex(match)
                        if decoded and self.contains_flag_pattern(decoded):
                            result_entry = {
                                "line_number": line_number,
                                "content": line[:100] + "..." if len(line) > 100 else line,
                                "match": f"Hex: {match} -> {decoded}"
                            }
                            results.append(result_entry)
                            
                            print(f"在第{line_number}行发现Hex编码的FLAG: {match} -> {decoded}")
                            
        except Exception as e:
            self.analysis_process.append({"step": "错误", "details": f"读取日志文件时出错: {str(e)}"})
            print(f"读取日志文件时出错: {str(e)}")
            raise Exception(f"读取日志文件时出错: {str(e)}")
            
        self.analysis_process.append({"step": "分析完成", "details": f"日志分析完成，共处理{line_number}行，发现{len(results)}条记录"})
        return results
    
    def find_base64_in_line(self, line):
        """在行中查找可能的base64编码字符串"""
        # base64字符串通常至少包含16个字符，且只包含特定字符
        potential_b64 = re.findall(r'[A-Za-z0-9+/]{16,}(?:={0,2})?', line)
        self.analysis_process.append({"step": "Base64查找", "details": f"在行中找到{len(potential_b64)}个潜在Base64字符串"})
        return potential_b64
    
    def try_decode_base64(self, s):
        """尝试解码base64字符串"""
        try:
            # 确保长度是4的倍数
            padding = 4 - (len(s) % 4)
            if padding != 4:
                s += "=" * padding
            
            decoded_bytes = base64.b64decode(s, validate=True)
            result = decoded_bytes.decode('utf-8', errors='ignore')
            self.analysis_process.append({"step": "Base64解码", "details": f"成功解码Base64字符串，长度: {len(result)}"})
            return result
        except Exception as e:
            self.analysis_process.append({"step": "Base64解码失败", "details": f"Base64解码失败: {str(e)}"})
            return None
    
    def find_hex_in_line(self, line):
        """在行中查找可能的十六进制编码字符串"""
        # 查找连续的十六进制字符，至少16个字符（8个字节）
        potential_hex = re.findall(r'[0-9a-fA-F]{16,}', line)
        self.analysis_process.append({"step": "Hex查找", "details": f"在行中找到{len(potential_hex)}个潜在Hex字符串"})
        return potential_hex
    
    def try_decode_hex(self, s):
        """尝试解码十六进制字符串"""
        try:
            # 确保长度是偶数
            if len(s) % 2 != 0:
                s = s[:-1]  # 去掉最后一个字符
                
            decoded_bytes = bytes.fromhex(s)
            result = decoded_bytes.decode('utf-8', errors='ignore')
            self.analysis_process.append({"step": "Hex解码", "details": f"成功解码Hex字符串，长度: {len(result)}"})
            return result
        except Exception as e:
            self.analysis_process.append({"step": "Hex解码失败", "details": f"Hex解码失败: {str(e)}"})
            return None
    
    def contains_flag_pattern(self, text):
        """检查文本是否包含flag模式"""
        flag_patterns = [
            r'(flag|FLAG|CTF|ctf)\{[^}]*\}',
            r'(flag|FLAG|CTF|ctf)\([^)]*\)',
            r'(flag|FLAG|CTF|ctf)\[[^\]]*\]',
        ]
        
        for pattern in flag_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                self.analysis_process.append({"step": "Flag匹配", "details": f"在文本中找到Flag模式: {pattern}"})
                return True
        return False


class LogAnalyzer(QObject):
    """日志分析器主类"""
    analysis_finished = Signal(list)  # 发送分析结果
    analysis_error = Signal(str)      # 发送错误信息
    
    def __init__(self):
        super().__init__()
        self.thread = None
        self.worker = None
    
    def analyze(self, log_file):
        """开始分析日志文件"""
        # 创建线程和工作对象
        self.thread = QThread()
        self.worker = LogAnalyzerWorker(log_file)
        
        # 移动工作对象到线程
        self.worker.moveToThread(self.thread)
        
        # 连接信号和槽
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_analysis_finished)
        self.worker.error.connect(self.on_analysis_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.error.connect(self.thread.quit)
        self.thread.finished.connect(self.thread.deleteLater)
        
        # 启动线程
        self.thread.start()
    
    def on_analysis_finished(self, results):
        """分析完成回调"""
        self.analysis_finished.emit(results)
        if self.worker:
            self.worker.deleteLater()
    
    def on_analysis_error(self, error_msg):
        """分析出错回调"""
        self.analysis_error.emit(error_msg)
        if self.worker:
            self.worker.deleteLater()