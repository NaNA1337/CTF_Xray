#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
文件/内存分析模块
用于分析文件系统镜像和内存转储，查找可能包含flag的内容
"""

import os
import re
import subprocess
from PySide6.QtCore import QObject, Signal, QThread
import json


class FileAnalyzerWorker(QObject):
    """文件分析工作线程"""
    finished = Signal(list)  # 发送分析结果
    error = Signal(str)      # 发送错误信息
    
    def __init__(self, file_paths):
        super().__init__()
        self.file_paths = file_paths if isinstance(file_paths, list) else [file_paths]
        self.analysis_process = []  # 存储分析过程
        
    def run(self):
        """执行分析任务"""
        try:
            print("=" * 50)
            print(f"开始分析{len(self.file_paths)}个文件/目录")
            print("=" * 50)
            
            results = self.analyze_files()
            # 将分析过程添加到结果中
            results.append({"type": "ANALYSIS_PROCESS", "content": json.dumps(self.analysis_process, ensure_ascii=False)})
            
            print("=" * 50)
            print(f"文件分析完成，共处理{len(results)-1}条记录")  # -1是因为包含了ANALYSIS_PROCESS
            print("=" * 50)
            
            self.finished.emit(results)
        except Exception as e:
            print("=" * 50)
            print(f"文件分析出错: {str(e)}")
            print("=" * 50)
            self.error.emit(str(e))
    
    def analyze_files(self):
        """
        分析文件/目录
        返回包含发现的flag相关数据的列表
        """
        results = []
        
        self.analysis_process.append({"step": "开始分析", "details": f"开始分析{len(self.file_paths)}个文件/目录"})
        
        for path in self.file_paths:
            if os.path.isfile(path):
                # 处理单个文件
                self.analysis_process.append({"step": "文件分析", "details": f"开始分析文件: {path}"})
                print(f"开始分析文件: {path}")
                file_results = self.analyze_single_file(path)
                results.extend(file_results)
            elif os.path.isdir(path):
                # 递归处理目录
                self.analysis_process.append({"step": "目录分析", "details": f"开始分析目录: {path}"})
                print(f"开始分析目录: {path}")
                dir_results = self.analyze_directory(path)
                results.extend(dir_results)
                
        self.analysis_process.append({"step": "分析完成", "details": f"文件分析完成，共处理{len(results)}条记录"})
        return results
    
    def analyze_single_file(self, file_path):
        """分析单个文件"""
        results = []
        
        try:
            # 获取文件基本信息
            file_size = os.path.getsize(file_path)
            _, file_extension = os.path.splitext(file_path)
            file_extension = file_extension.lower()
            
            self.analysis_process.append({"step": "文件信息", "details": f"文件大小: {file_size} bytes, 扩展名: {file_extension}"})
            print(f"文件信息 - 大小: {file_size} bytes, 扩展名: {file_extension}")
            
            # 根据文件类型采用不同的分析策略
            if file_extension in ['.png', '.jpg', '.jpeg', '.bmp', '.gif']:
                # 图片文件 - 检查LSB隐写
                self.analysis_process.append({"step": "图片分析", "details": f"检测到图片文件: {file_path}"})
                print(f"检测到图片文件: {file_path}")
                stego_result = self.check_image_steganography(file_path)
                if stego_result:
                    result_entry = {
                        "path": file_path,
                        "type": "IMAGE_STEGO",
                        "content": stego_result
                    }
                    results.append(result_entry)
                    print(f"图片隐写分析结果: {stego_result}")
            
            elif file_extension in ['.zip', '.rar', '.7z']:
                # 压缩文件 - 检查伪加密
                self.analysis_process.append({"step": "压缩文件分析", "details": f"检测到压缩文件: {file_path}"})
                print(f"检测到压缩文件: {file_path}")
                crypto_result = self.check_crypto_archive(file_path)
                if crypto_result:
                    result_entry = {
                        "path": file_path,
                        "type": "ARCHIVE_CRYPTO",
                        "content": crypto_result
                    }
                    results.append(result_entry)
                    print(f"压缩文件分析结果: {crypto_result}")
            
            elif file_extension in ['.pdf']:
                # PDF文件 - 检查元数据
                self.analysis_process.append({"step": "PDF分析", "details": f"检测到PDF文件: {file_path}"})
                print(f"检测到PDF文件: {file_path}")
                pdf_result = self.check_pdf_metadata(file_path)
                if pdf_result:
                    result_entry = {
                        "path": file_path,
                        "type": "PDF_METADATA",
                        "content": pdf_result
                    }
                    results.append(result_entry)
                    print(f"PDF文件分析结果: {pdf_result}")
            
            # 对所有文件都进行字符串提取
            self.analysis_process.append({"step": "字符串提取", "details": f"开始提取文件字符串: {file_path}"})
            print(f"开始提取文件字符串: {file_path}")
            strings_result = self.extract_strings_with_flags(file_path)
            results.extend(strings_result)
            
        except Exception as e:
            self.analysis_process.append({"step": "错误", "details": f"分析文件时出错: {str(e)}"})
            print(f"分析文件时出错: {str(e)}")
            results.append({
                "path": file_path,
                "type": "ERROR",
                "content": f"分析文件时出错: {str(e)}"
            })
            
        return results
    
    def analyze_directory(self, dir_path):
        """递归分析目录"""
        results = []
        
        try:
            self.analysis_process.append({"step": "目录遍历", "details": f"开始遍历目录: {dir_path}"})
            print(f"开始遍历目录: {dir_path}")
            file_count = 0
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_count += 1
                    file_path = os.path.join(root, file)
                    file_results = self.analyze_single_file(file_path)
                    results.extend(file_results)
            self.analysis_process.append({"step": "目录遍历完成", "details": f"目录遍历完成，共处理{file_count}个文件"})
            print(f"目录遍历完成，共处理{file_count}个文件")
        except Exception as e:
            self.analysis_process.append({"step": "错误", "details": f"遍历目录时出错: {str(e)}"})
            print(f"遍历目录时出错: {str(e)}")
            results.append({
                "path": dir_path,
                "type": "ERROR",
                "content": f"遍历目录时出错: {str(e)}"
            })
            
        return results
    
    def extract_strings_with_flags(self, file_path):
        """提取文件中的字符串并查找flag"""
        results = []
        
        try:
            # 使用strings命令提取可打印字符串（如果可用）
            strings_output = self.run_strings_command(file_path)
            if strings_output:
                self.analysis_process.append({"step": "Strings命令", "details": f"strings命令执行成功，输出长度: {len(strings_output)}"})
                print(f"strings命令执行成功，输出长度: {len(strings_output)}")
                flag_patterns = [
                    r'(flag|FLAG|CTF|ctf)\{[^}]*\}',
                    r'(flag|FLAG|CTF|ctf)\([^)]*\)',
                    r'(flag|FLAG|CTF|ctf)\[[^\]]*\]',
                ]
                
                lines = strings_output.split('\n')
                match_count = 0
                for i, line in enumerate(lines):
                    for pattern in flag_patterns:
                        matches = re.findall(pattern, line, re.IGNORECASE)
                        for match in matches:
                            match_count += 1
                            result_entry = {
                                "path": file_path,
                                "type": "STRING_MATCH",
                                "content": f"Line {i+1}: {match}"
                            }
                            results.append(result_entry)
                            print(f"在文件 {file_path} 的第{i+1}行发现匹配: {match}")
                self.analysis_process.append({"step": "字符串匹配", "details": f"字符串匹配完成，找到{match_count}个匹配项"})
            
            # 如果strings命令不可用，使用简单的方法读取
            if not results:  # 简化处理，总是尝试这种方法
                with open(file_path, 'rb') as f:
                    data = f.read()
                    # 查找ASCII字符串
                    ascii_strings = re.findall(b'[ -~]{4,}', data)
                    match_count = 0
                    for s in ascii_strings:
                        try:
                            s_str = s.decode('ascii')
                            if re.search(r'(flag|FLAG|CTF|ctf)[{\[(][^}\])]*[}\])]', s_str, re.IGNORECASE):
                                match_count += 1
                                result_entry = {
                                    "path": file_path,
                                    "type": "ASCII_STRING",
                                    "content": s_str[:100]  # 限制长度
                                }
                                results.append(result_entry)
                                print(f"在文件 {file_path} 中发现ASCII字符串: {s_str[:100]}")
                        except UnicodeDecodeError:
                            pass
                    self.analysis_process.append({"step": "ASCII字符串提取", "details": f"ASCII字符串提取完成，找到{match_count}个匹配项"})
                            
        except Exception as e:
            # 不记录错误，因为不是所有文件都能成功读取
            self.analysis_process.append({"step": "字符串提取错误", "details": f"字符串提取时出错: {str(e)}"})
            print(f"字符串提取时出错: {str(e)}")
            pass
            
        return results
    
    def run_strings_command(self, file_path):
        """运行strings命令提取可打印字符串"""
        try:
            # 尝试使用strings命令
            result = subprocess.run(['strings', file_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                self.analysis_process.append({"step": "Strings命令成功", "details": "strings命令执行成功"})
                return result.stdout
            else:
                self.analysis_process.append({"step": "Strings命令失败", "details": f"strings命令执行失败，返回码: {result.returncode}"})
                print(f"strings命令执行失败，返回码: {result.returncode}")
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            # strings命令不可用或超时
            self.analysis_process.append({"step": "Strings命令不可用", "details": f"strings命令不可用或超时: {str(e)}"})
            print(f"strings命令不可用或超时: {str(e)}")
            pass
        return None
    
    def check_image_steganography(self, file_path):
        """检查图片隐写（简化版）"""
        # 这里只是一个占位实现
        # 在完整实现中，可以使用steghide、zsteg等工具
        
        # 检查文件头是否有异常
        try:
            with open(file_path, 'rb') as f:
                header = f.read(100)
                # 检查是否有可疑的头部信息
                if b'flag' in header.lower() or b'ctf' in header.lower():
                    self.analysis_process.append({"step": "图片隐写检查", "details": "图片文件头包含可疑信息"})
                    print("图片文件头包含可疑信息")
                    return "图片文件头包含可疑信息"
        except Exception as e:
            self.analysis_process.append({"step": "图片隐写检查错误", "details": f"图片隐写检查时出错: {str(e)}"})
            print(f"图片隐写检查时出错: {str(e)}")
            pass
            
        self.analysis_process.append({"step": "图片隐写检查完成", "details": "未发现明显隐写痕迹"})
        return None
    
    def check_crypto_archive(self, file_path):
        """检查压缩包加密（简化版）"""
        # 这里只是一个占位实现
        # 在完整实现中，可以检查ZIP的加密标志位等
        
        try:
            # 检查文件名是否有线索
            if 'flag' in file_path.lower() or 'ctf' in file_path.lower():
                self.analysis_process.append({"step": "压缩包检查", "details": "文件名包含flag关键词"})
                print("文件名包含flag关键词")
                return "文件名包含flag关键词"
        except Exception as e:
            self.analysis_process.append({"step": "压缩包检查错误", "details": f"压缩包检查时出错: {str(e)}"})
            print(f"压缩包检查时出错: {str(e)}")
            pass
            
        self.analysis_process.append({"step": "压缩包检查完成", "details": "未发现明显加密线索"})
        return None
    
    def check_pdf_metadata(self, file_path):
        """检查PDF元数据（简化版）"""
        # 这里只是一个占位实现
        # 在完整实现中，可以使用PyPDF2等库读取元数据
        
        try:
            # 检查文件名是否有线索
            if 'flag' in file_path.lower() or 'ctf' in file_path.lower():
                self.analysis_process.append({"step": "PDF检查", "details": "文件名包含flag关键词"})
                print("文件名包含flag关键词")
                return "文件名包含flag关键词"
        except Exception as e:
            self.analysis_process.append({"step": "PDF检查错误", "details": f"PDF检查时出错: {str(e)}"})
            print(f"PDF检查时出错: {str(e)}")
            pass
            
        self.analysis_process.append({"step": "PDF检查完成", "details": "未发现明显元数据线索"})
        return None


class FileAnalyzer(QObject):
    """文件分析器主类"""
    analysis_finished = Signal(list)  # 发送分析结果
    analysis_error = Signal(str)      # 发送错误信息
    
    def __init__(self):
        super().__init__()
        self.thread = None
        self.worker = None
    
    def analyze(self, file_paths):
        """开始分析文件"""
        # 创建线程和工作对象
        self.thread = QThread()
        self.worker = FileAnalyzerWorker(file_paths)
        
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