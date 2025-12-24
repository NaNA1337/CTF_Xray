#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络流量分析模块
用于分析pcap文件，提取可能包含flag的信息
"""

import re
from PySide6.QtCore import QObject, Signal, QThread
import json
import pyshark
import asyncio
import platform
import os
import tempfile
import shutil
from pathlib import Path


def get_tcp_segment(pkt):
    """从pyshark数据包中解码TCP十六进制payload为原始字节"""
    if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"):
        return bytes.fromhex(str(pkt.tcp.payload).replace(":", ""))
    return b""


class PcapAnalyzerWorker(QObject):
    """PCAP分析工作线程"""
    finished = Signal(list)  # 发送分析结果
    error = Signal(str)      # 发送错误信息
    
    def __init__(self, pcap_file):
        super().__init__()
        self.pcap_file = pcap_file
        self.analysis_process = []  # 存储分析过程
        
    def run(self):
        """执行分析任务"""
        try:
            # 在Windows上创建新的事件循环，以处理pyshark的异步操作
            if platform.system() == 'Windows':
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            
            # 为当前线程创建新的事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            print("=" * 50)
            print(f"开始分析PCAP文件: {self.pcap_file}")
            print("=" * 50)
            
            # 检查文件大小，决定是否使用分块模式
            file_size = os.path.getsize(self.pcap_file)
            print(f"文件大小: {file_size / 1024 / 1024:.2f} MB")
            
            # 使用统一的分块分析模式
            print("使用分块分析模式处理PCAP文件")
            results = self.analyze_pcap()
            
            # 将分析过程添加到结果中
            results.append({"type": "ANALYSIS_PROCESS", "content": json.dumps(self.analysis_process, ensure_ascii=False)})
            
            print("=" * 50)
            print(f"PCAP分析完成，共发现{len(results)-1}条记录")  # -1是因为包含了ANALYSIS_PROCESS
            print("=" * 50)
            
            self.finished.emit(results)
        except Exception as e:
            print("=" * 50)
            print(f"PCAP分析出错: {str(e)}")
            import traceback
            traceback.print_exc()
            print("=" * 50)
            self.error.emit(str(e))
        finally:
            # 关闭事件循环
            try:
                loop = asyncio.get_event_loop()
                if loop and not loop.is_closed():
                    loop.close()
            except:
                pass
    
    def analyze_pcap(self):
        """
        分析PCAP文件（非分块模式）
        返回包含所有数据包完整JSON的列表
        """
        results = []
        cap = None
        packets = []
        
        # 记录分析步骤
        self.analysis_process.append({"step": "开始分析", "details": f"开始分析PCAP文件: {self.pcap_file}"})
        
        # 检查是否可以加载pcap文件
        try:
            # 在工作线程中创建pyshark.FileCapture，禁用异步以避免事件循环问题
            cap = pyshark.FileCapture(self.pcap_file, keep_packets=False, use_json=True)
            # 加载所有数据包到内存
            try:
                packets = list(cap)
                packet_count = len(packets)
            except Exception as count_e:
                print(f"加载数据包时出错: {str(count_e)}")
                self.analysis_process.append({"step": "数据包加载", "details": f"加载了{len(packets)}个数据包"})
            
            if cap:
                cap.close()
            
            if not packets:
                self.analysis_process.append({"step": "数据包加载", "details": "没有找到任何数据包"})
                return results
            
            self.analysis_process.append({"step": "环境检查", "details": f"pyshark库可用，成功加载PCAP文件，共{packet_count}个数据包"})
        except Exception as e:
            self.analysis_process.append({"step": "环境检查", "details": f"pyshark库不可用或无法加载PCAP文件: {str(e)}"})
            raise Exception(f"无法加载PCAP文件: {str(e)}")
        
        # 统一处理所有数据包，输出到单个JSON文件
        try:
            total_packets = len(packets)
            self.analysis_process.append({"step": "数据包分析", "details": f"开始分析{total_packets}个数据包"})
            print(f"[分析] 开始分析 {total_packets} 个数据包...")
            
            # 分析所有数据包
            all_packets_json = self._analyze_all_packets(packets)
            
            # 保存到单个JSON文件
            tmp_dir = Path("tmp")
            if not tmp_dir.exists():
                tmp_dir.mkdir(exist_ok=True)
            
            json_filepath = tmp_dir / "all_packets.json"
            with open(json_filepath, 'w', encoding='utf-8') as f:
                json.dump(all_packets_json, f, indent=2, ensure_ascii=False)
            
            results.append({
                "type": "PACKETS_JSON",
                "packet_count": len(all_packets_json),
                "json_file": str(json_filepath),
                "content": f"[数据包分析完成，已保存到: {json_filepath}]"
            })
            
            print(f"[分析] 共分析 {len(all_packets_json)} 个数据包，已保存到 {json_filepath}")
            self.analysis_process.append({"step": "数据包分析完成", "details": f"已分析 {len(all_packets_json)} 个数据包，保存到JSON文件"})
        
        except Exception as e:
            self.analysis_process.append({"step": "分析错误", "details": f"数据包分析出错: {str(e)}"})
            print(f"分析出错: {str(e)}")
            raise
        finally:
            try:
                if cap:
                    cap.close()
            except:
                pass
        
        self.analysis_process.append({"step": "分析完成", "details": f"分析完成，共发现{len(results)}条记录"})
        return results
    
    def _analyze_all_packets(self, packets):
        """
        分析所有数据包，输出到单个JSON文件
        对所有数据包进行完整解包和分析
        """
        decompiler = PacketDecompiler()
        packets_json = []
        
        print(f"[分析] 开始解包 {len(packets)} 个数据包...")
        
        for idx, packet in enumerate(packets, 1):
            try:
                # 完整解包
                decompiled = decompiler.decompile_packet(packet)
                packets_json.append(decompiled)
            except Exception as e:
                print(f"[错误] 解包数据包 #{idx} 失败: {e}")
                # 即使解包失败，也添加基础信息
                packets_json.append({
                    "packet_id": str(packet.frame_info.number),
                    "timestamp": str(packet.frame_info.time),
                    "packet_length": int(packet.frame_info.len),
                    "protocols": packet.frame_info.protocols.split(':'),
                    "error": str(e)
                })
            
            # 每100个包输出一次进度
            if idx % 100 == 0:
                print(f"[进度] 已解包 {idx}/{len(packets)} 个数据包")
        
        print(f"[完成] 共解包 {len(packets_json)} 个数据包")
        return packets_json
    
    def _analyze_chunk(self, chunk_packets, chunk_id, total_chunks):
        """
        分析单个数据块
        提取该块中所有可疑内容供AI分析
        将JSON保存到tmp文件夹以节省内存
        """
        results = []
        
        # 创建tmp文件夹（如果不存在）
        tmp_dir = Path("tmp")
        if not tmp_dir.exists():
            tmp_dir.mkdir(exist_ok=True)
        
        # 添加块头
        results.append({
            "type": "CHUNK_START",
            "chunk_id": chunk_id,
            "total_chunks": total_chunks,
            "packet_count": len(chunk_packets),
            "content": f"\n{'='*60}\n【数据块 {chunk_id}/{total_chunks}】\n包含 {len(chunk_packets)} 个数据包\n{'='*60}\n"
        })
        
        # 对该块的数据包进行完整JSON导出
        try:
            decompiler = PacketDecompiler()
            
            # 导出所有包的完整JSON信息
            packets_json = []
            for packet in chunk_packets:
                try:
                    # 完整解包
                    decompiled = decompiler.decompile_packet(packet)
                    packets_json.append(decompiled)
                except Exception as e:
                    print(f"解包数据包失败: {e}")
                    # 即使解包失败，也添加基础信息
                    packets_json.append({
                        "packet_id": str(packet.frame_info.number),
                        "timestamp": str(packet.frame_info.time),
                        "packet_length": int(packet.frame_info.len),
                        "protocols": packet.frame_info.protocols.split(':'),
                        "error": str(e)
                    })
            
            # 添加JSON导出结果 - 保存到文件而不是内存
            if packets_json:
                json_content = json.dumps(packets_json, ensure_ascii=False, indent=2)
                
                # 保存JSON到tmp文件
                json_filename = f"chunk_{chunk_id:03d}.json"
                json_filepath = tmp_dir / json_filename
                with open(json_filepath, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                
                results.append({
                    "type": "PACKETS_JSON",
                    "chunk_id": chunk_id,
                    "packet_count": len(packets_json),
                    "json_file": str(json_filepath),  # 文件路径而不是内容
                    "content": f"[JSON数据已保存到文件: {json_filepath}]",  # 简化内容，避免大数据
                    "packets_data": packets_json  # 仅在本地使用
                })
                
                print(f"[块{chunk_id}] 导出 {len(packets_json)} 个数据包的完整JSON到 {json_filepath}")
        
        except Exception as e:
            print(f"JSON导出失败: {e}")
        
        # 添加块尾
        results.append({
            "type": "CHUNK_SUMMARY",
            "chunk_id": chunk_id,
            "content": f"【块 {chunk_id} 分析完成】 导出 {len(chunk_packets)} 个数据包的完整JSON\n"
        })
        
        return results
    
    def export_all_data(self, cap):
        """导出所有数据包信息供AI参考分析"""
        results = []
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    # 获取基本的IP信息
                    src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    
                    # 获取端口信息
                    src_port = 'N/A'
                    dst_port = 'N/A'
                    if hasattr(packet, 'tcp'):
                        src_port = getattr(packet.tcp, 'srcport', 'N/A')
                        dst_port = getattr(packet.tcp, 'dstport', 'N/A')
                    elif hasattr(packet, 'udp'):
                        src_port = getattr(packet.udp, 'srcport', 'N/A')
                        dst_port = getattr(packet.udp, 'dstport', 'N/A')
                    
                    # 获取数据内容
                    data_content = 'N/A'
                    if hasattr(packet, 'data'):
                        data_content = getattr(packet.data, 'data', 'N/A')
                    elif 'TCP' in packet and hasattr(packet.tcp, 'payload'):
                        data_content = packet.tcp.payload
                    elif 'UDP' in packet and hasattr(packet.udp, 'payload'):
                        data_content = packet.udp.payload
                    elif 'HTTP' in packet and hasattr(packet.http, 'file_data'):
                        data_content = packet.http.file_data
                    elif 'HTTP' in packet and hasattr(packet.http, 'request_uri'):
                        data_content = f"{getattr(packet.http, 'request_method', 'GET')} {getattr(packet.http, 'request_uri', '')}"
                    elif 'HTTP' in packet and hasattr(packet.http, 'response_code'):
                        data_content = f"Response Code: {getattr(packet.http, 'response_code', '')}"
                    
                    # 尝试解码数据
                    decoded_data = data_content
                    if data_content != 'N/A':
                        try:
                            # 尝试将十六进制字符串转换为可读文本
                            if isinstance(data_content, str) and all(c in '0123456789abcdefABCDEF' for c in data_content.replace(':', '')):
                                decoded_data = bytes.fromhex(data_content.replace(':', '')).decode('utf-8', errors='ignore')
                            else:
                                decoded_data = data_content
                        except:
                            decoded_data = data_content
                    
                    result_entry = {
                        "type": "ALL_DATA",
                        "src": f"{src_ip}:{src_port}" if src_port != 'N/A' else src_ip,
                        "dst": f"{dst_ip}:{dst_port}" if dst_port != 'N/A' else dst_ip,
                        "content": f"Frame {packet_num} Len:{len(str(packet))} Data:{decoded_data[:100]}{'...' if len(decoded_data) > 100 else ''}"
                    }
                    results.append(result_entry)
                    
                    print(f"导出数据: {result_entry['content']}")
                    
                except AttributeError:
                    # 某些数据包可能没有IP层
                    continue
                except Exception as e:
                    print(f"处理数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理失败: {str(e)}"})
            print(f"pyshark处理失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "全部数据导出完成", "details": f"全部数据导出完成，导出{len(results)}条记录"})
        return results
    
    def search_flag_in_pcap(self, cap):
        """在pcap中搜索flag相关字符串，使用正则表达式进行精确匹配"""
        results = []
        # 常见的flag格式正则表达式
        flag_patterns = [
            r'flag\{[^}]+\}',  # flag{...}
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[A-Za-z0-9_]{20,}',  # 长字符串可能是加密的flag
            r'[a-f0-9]{32}',  # MD5可能的hash
            r'[a-f0-9]{40}',  # SHA1可能的hash
            r'[a-f0-9]{64}',  # SHA256可能的hash
        ]
        
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    # 获取完整的数据包信息
                    src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    
                    # 收集所有可能包含数据的内容
                    packet_contents = []
                    
                    # 获取协议数据
                    if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                        packet_contents.append(str(getattr(packet.tcp, 'payload', '')))
                    elif hasattr(packet, 'udp') and hasattr(packet.udp, 'payload'):
                        packet_contents.append(str(getattr(packet.udp, 'payload', '')))
                    
                    if hasattr(packet, 'http'):
                        if hasattr(packet.http, 'file_data'):
                            packet_contents.append(str(getattr(packet.http, 'file_data', '')))
                        if hasattr(packet.http, 'request_uri'):
                            packet_contents.append(str(getattr(packet.http, 'request_uri', '')))
                        if hasattr(packet.http, 'request_body'):
                            packet_contents.append(str(getattr(packet.http, 'request_body', '')))
                    
                    if hasattr(packet, 'data'):
                        packet_contents.append(str(getattr(packet.data, 'data', '')))
                    
                    # 对所有内容进行正则匹配
                    for content in packet_contents:
                        for pattern in flag_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                # 解码十六进制数据
                                decoded_match = match
                                try:
                                    if all(c in '0123456789abcdefABCDEF' for c in match.replace(':', '')):
                                        decoded_match = bytes.fromhex(match.replace(':', '')).decode('utf-8', errors='ignore')
                                except:
                                    pass
                                
                                result_entry = {
                                    "type": "FLAG_REGEX_MATCH",
                                    "src": src_ip,
                                    "dst": dst_ip,
                                    "match": decoded_match,
                                    "content": f"Frame {packet_num}: 正则匹配到可能的flag: {decoded_match}"
                                }
                                results.append(result_entry)
                                print(f"[FLAG正则匹配] {decoded_match}")
                    
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理FLAG搜索失败: {str(e)}"})
            print(f"pyshark处理FLAG搜索失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "FLAG搜索完成", "details": f"FLAG搜索完成，发现{len(results)}条记录"})
        return results
    
    def extract_tcp_streams_detailed(self, cap):
        """提取TCP流的详细信息，包括完整内容和协议字段"""
        results = []
        tcp_streams = {}  # 用于组合TCP流
        
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    if hasattr(packet, 'tcp'):
                        # 获取TCP基本信息
                        src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        src_port = getattr(packet.tcp, 'srcport', 'N/A')
                        dst_port = getattr(packet.tcp, 'dstport', 'N/A')
                        seq = getattr(packet.tcp, 'seq', 'N/A')
                        ack = getattr(packet.tcp, 'ack', 'N/A')
                        flags = getattr(packet.tcp, 'flags', 'N/A')
                        
                        # 创建流标识符
                        stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                        
                        # 提取payload内容
                        payload = 'N/A'
                        if hasattr(packet.tcp, 'payload'):
                            payload = getattr(packet.tcp, 'payload', '')
                        
                        # 尝试提取应用层数据
                        app_data = ''
                        if hasattr(packet, 'http'):
                            # HTTP数据
                            if hasattr(packet.http, 'file_data'):
                                app_data = getattr(packet.http, 'file_data', '')
                            elif hasattr(packet.http, 'request_line'):
                                app_data = f"HTTP {getattr(packet.http, 'request_method', '')} {getattr(packet.http, 'request_uri', '')}"
                        
                        # 构建详细内容
                        tcp_detail = {
                            "packet": packet_num,
                            "seq": seq,
                            "ack": ack,
                            "flags": flags,
                            "payload": payload[:200] if payload and payload != 'N/A' else 'N/A',  # 截断超长内容
                            "app_data": app_data
                        }
                        
                        # 累积TCP流
                        if stream_key not in tcp_streams:
                            tcp_streams[stream_key] = {
                                "src": f"{src_ip}:{src_port}",
                                "dst": f"{dst_ip}:{dst_port}",
                                "packets": [],
                                "all_payload": "",
                                "all_app_data": ""
                            }
                        
                        tcp_streams[stream_key]["packets"].append(tcp_detail)
                        if payload and payload != 'N/A':
                            tcp_streams[stream_key]["all_payload"] += str(payload)
                        if app_data:
                            tcp_streams[stream_key]["all_app_data"] += str(app_data) + "\n"
                
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理TCP数据包 {packet_num} 时出错: {str(e)}")
                    continue
            
            # 输出TCP流信息
            for stream_key, stream_data in tcp_streams.items():
                # 生成详细的流摘要
                packet_count = len(stream_data["packets"])
                
                # 尝试解析payload
                decoded_payload = stream_data["all_payload"]
                try:
                    # 尝试从十六进制解码
                    if decoded_payload and all(c in '0123456789abcdefABCDEF:' for c in str(decoded_payload)):
                        decoded_payload = bytes.fromhex(decoded_payload.replace(':', '')).decode('utf-8', errors='ignore')
                except:
                    pass

                # 构建内容信息
                content_info = f"TCP流: {stream_data['src']} -> {stream_data['dst']}\n"
                content_info += f"数据包数: {packet_count}\n"
                if decoded_payload:
                    decoded_text = self._decode_hex_to_text(decoded_payload, max_len=2000)
                    content_info += f"完整Payload(Text): {decoded_text[:500]}\n"
                content_info += f"应用层数据: {stream_data['all_app_data'][:500]}" if stream_data['all_app_data'] else ""
                
                # 详细的协议字段
                protocol_details = []
                for pkt in stream_data["packets"]:
                    if pkt['flags'] != 'N/A':
                        protocol_details.append(f"Pkt{pkt['packet']}: seq={pkt['seq']}, ack={pkt['ack']}, flags={pkt['flags']}")
                
                result_entry = {
                    "type": "TCP_STREAM",
                    "src": stream_data['src'],
                    "dst": stream_data['dst'],
                    "content": content_info,
                    "protocol_details": "\n".join(protocol_details[:10]),  # 仅保留前10个数据包的详情
                    "packet_count": packet_count,
                    "payload": decoded_payload[:1000],  # 原始聚合payload
                    "payload_text": decoded_text[:1000] if decoded_payload else ""  # 文本化payload
                }
                results.append(result_entry)
                
                print(f"发现TCP流: {stream_data['src']} -> {stream_data['dst']}, {packet_count}个数据包")
        
        except Exception as e:
            self.analysis_process.append({"step": "TCP流提取错误", "details": f"TCP流提取失败: {str(e)}"})
            print(f"TCP流提取失败: {str(e)}")
        
        self.analysis_process.append({"step": "TCP流提取完成", "details": f"TCP流提取完成，发现{len(results)}条流"})
        return results
    
    def extract_http_streams(self, cap):
        """提取HTTP流信息"""
        results = []
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    if 'HTTP' in packet:
                        src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        
                        # 获取HTTP字段
                        method = getattr(packet.http, 'request_method', '') if hasattr(packet.http, 'request_method') else ''
                        uri = getattr(packet.http, 'request_uri', '') if hasattr(packet.http, 'request_uri') else ''
                        response_code = getattr(packet.http, 'response_code', '') if hasattr(packet.http, 'response_code') else ''
                        host = getattr(packet.http, 'host', '') if hasattr(packet.http, 'host') else ''
                        user_agent = getattr(packet.http, 'user_agent', '') if hasattr(packet.http, 'user_agent') else ''
                        content_type = getattr(packet.http, 'content_type', '') if hasattr(packet.http, 'content_type') else ''
                        
                        # 构建HTTP信息
                        http_info = f"HTTP {method} {uri}" if method else f"HTTP Response {response_code}"
                        if host:
                            http_info += f" Host:{host}"
                        if response_code and response_code != "":
                            http_info += f" Response:{response_code}"
                        if user_agent:
                            http_info += f" UA:{user_agent[:50]}{'...' if len(user_agent) > 50 else ''}"
                        if content_type:
                            http_info += f" Content-Type:{content_type}"
                        
                        result_entry = {
                            "type": "HTTP",
                            "src": src_ip,
                            "dst": dst_ip,
                            "content": http_info
                        }
                        results.append(result_entry)
                        
                        print(f"发现HTTP流: {result_entry['content']}")
                        
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理HTTP数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理HTTP流提取失败: {str(e)}"})
            print(f"pyshark处理HTTP流提取失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "HTTP流提取完成", "details": f"HTTP流提取完成，发现{len(results)}条记录"})
        return results
    
    def extract_http_content(self, cap):
        """提取HTTP内容，包括请求体和响应体"""
        results = []
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    if 'HTTP' in packet:
                        full_uri = getattr(packet.http, 'request_full_uri', '') if hasattr(packet.http, 'request_full_uri') else ''
                        method = getattr(packet.http, 'request_method', '') if hasattr(packet.http, 'request_method') else ''
                        query = getattr(packet.http, 'request_uri', '') if hasattr(packet.http, 'request_uri') else ''
                        req_body = getattr(packet.http, 'file_data', '') if hasattr(packet.http, 'file_data') else ''
                        resp_code = getattr(packet.http, 'response_code', '') if hasattr(packet.http, 'response_code') else ''
                        resp_phrase = getattr(packet.http, 'response_phrase', '') if hasattr(packet.http, 'response_phrase') else ''
                        resp_body = getattr(packet.http, 'file_data', '') if hasattr(packet.http, 'file_data') else ''
                        content_type = getattr(packet.http, 'content_type', '') if hasattr(packet.http, 'content_type') else ''
                        user_agent = getattr(packet.http, 'user_agent', '') if hasattr(packet.http, 'user_agent') else ''
                        referer = getattr(packet.http, 'referer', '') if hasattr(packet.http, 'referer') else ''
                        
                        # 构建HTTP内容信息
                        http_content = ""
                        if full_uri:
                            http_content += f"URI: {full_uri} | "
                        if method:
                            http_content += f"Method: {method} | "
                        if query:
                            http_content += f"Query: {query} | "
                        if user_agent:
                            http_content += f"User-Agent: {user_agent} | "
                        if referer:
                            http_content += f"Referer: {referer} | "
                        if content_type:
                            http_content += f"Content-Type: {content_type} | "
                        if req_body and req_body != resp_body:
                            http_content += f"RequestBody: {req_body} | "
                        if resp_code:
                            http_content += f"ResponseCode: {resp_code} | "
                        if resp_phrase:
                            http_content += f"ResponsePhrase: {resp_phrase} | "
                        if resp_body and req_body != resp_body:  # 避免重复
                            http_content += f"ResponseBody: {resp_body}"
                        
                        # 如果没有具体数据，至少包含基本的HTTP信息
                        if not http_content.strip():
                            http_content = f"HTTP {method} {query} Response: {resp_code}"
                        
                        result_entry = {
                            "type": "HTTP_CONTENT",
                            "src": getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A',
                            "dst": getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A',
                            "content": http_content
                        }
                        results.append(result_entry)
                        
                        print(f"发现HTTP内容: {result_entry['content']}")
                        
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理HTTP内容数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理HTTP内容提取失败: {str(e)}"})
            print(f"pyshark处理HTTP内容提取失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "HTTP内容提取完成", "details": f"HTTP内容提取完成，发现{len(results)}条记录"})
        return results
    
    def extract_dns_queries(self, cap):
        """提取DNS查询信息"""
        results = []
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    if 'DNS' in packet and hasattr(packet, 'dns'):
                        src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        
                        # 获取DNS字段
                        dns_query = getattr(packet.dns, 'qry_name', '') if hasattr(packet.dns, 'qry_name') else ''
                        dns_resp = getattr(packet.dns, 'resp_name', '') if hasattr(packet.dns, 'resp_name') else ''
                        dns_a = getattr(packet.dns, 'a', '') if hasattr(packet.dns, 'a') else ''
                        dns_qry_type = getattr(packet.dns, 'qry_type', '') if hasattr(packet.dns, 'qry_type') else ''
                        
                        # 构建DNS信息
                        dns_info = f"Query: {dns_query}"
                        if dns_qry_type:
                            dns_info += f" (Type: {dns_qry_type})"
                        if dns_resp:
                            dns_info += f" | Response: {dns_resp}"
                        if dns_a:
                            dns_info += f" | A-Record: {dns_a}"
                        
                        result_entry = {
                            "type": "DNS_FLAG",
                            "src": src_ip,
                            "dst": dst_ip,
                            "content": dns_info
                        }
                        results.append(result_entry)
                        
                        print(f"发现DNS: {result_entry['content']}")
                        
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理DNS数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理DNS查询提取失败: {str(e)}"})
            print(f"pyshark处理DNS查询提取失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "DNS查询提取完成", "details": f"DNS查询提取完成，发现{len(results)}条记录"})
        return results
    
    def extract_icmp_data(self, cap):
        """提取ICMP数据"""
        results = []
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    if 'ICMP' in packet or 'ICMPv6' in packet:
                        src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        
                        # 获取ICMP数据
                        icmp_data = ''
                        if hasattr(packet, 'icmp'):
                            icmp_data = str(packet.icmp)
                            icmp_type = getattr(packet.icmp, 'type', '')
                            icmp_code = getattr(packet.icmp, 'code', '')
                            icmp_data_field = getattr(packet.icmp, 'data', '')
                            icmp_info = f"ICMP Type: {icmp_type}, Code: {icmp_code}"
                            if icmp_data_field:
                                icmp_info += f", Data: {icmp_data_field}"
                            icmp_data = icmp_info
                        elif hasattr(packet, 'icmpv6'):
                            icmp_data = str(packet.icmpv6)
                            icmpv6_type = getattr(packet.icmpv6, 'type', '')
                            icmpv6_code = getattr(packet.icmpv6, 'code', '')
                            icmpv6_data_field = getattr(packet.icmpv6, 'data', '')
                            icmpv6_info = f"ICMPv6 Type: {icmpv6_type}, Code: {icmpv6_code}"
                            if icmpv6_data_field:
                                icmpv6_info += f", Data: {icmpv6_data_field}"
                            icmp_data = icmpv6_info
                        
                        # 尝试解码ICMP数据
                        try:
                            decoded_data = icmp_data
                            if isinstance(icmp_data, str) and all(c in '0123456789abcdefABCDEF' for c in icmp_data.replace(':', '')):
                                decoded_data = bytes.fromhex(icmp_data.replace(':', '')).decode('utf-8', errors='ignore')
                            
                            result_entry = {
                                "type": "ICMP_DATA",
                                "src": src_ip,
                                "dst": dst_ip,
                                "content": decoded_data
                            }
                            results.append(result_entry)
                            
                            print(f"发现ICMP数据: {result_entry['content']}")
                            
                        except:
                            # 如果无法解码，仍然添加原始数据
                            result_entry = {
                                "type": "ICMP_RAW",
                                "src": src_ip,
                                "dst": dst_ip,
                                "content": icmp_data
                            }
                            results.append(result_entry)
                            
                            print(f"发现ICMP原始数据: {result_entry['content']}")
                            
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理ICMP数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理ICMP数据提取失败: {str(e)}"})
            print(f"pyshark处理ICMP数据提取失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "ICMP数据提取完成", "details": f"ICMP数据提取完成，发现{len(results)}条记录"})
        return results


class PcapAnalyzer(QObject):
    """PCAP分析器主类"""
    analysis_finished = Signal(list)  # 发送分析结果
    analysis_error = Signal(str)      # 发送错误信息
    
    def __init__(self):
        super().__init__()
        self.thread = None
        self.worker = None
    
    def analyze(self, pcap_file):
        """开始分析PCAP文件"""
        # 创建线程和工作对象
        self.thread = QThread()
        self.worker = PcapAnalyzerWorker(pcap_file)
        
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


class PacketDecompiler:
    """数据包完整解包器 - 提供深层次的包分析和解包"""
    
    def __init__(self):
        self.packet_data = {}
    
    def decompile_packet(self, packet):
        """
        完整解包一个数据包，提取所有层级的信息
        """
        result = {
            "packet_id": str(packet.frame_info.number),
            "timestamp": str(packet.frame_info.time),
            "packet_length": int(packet.frame_info.len),
            "protocols": packet.frame_info.protocols.split(':'),
            "layers": {},
            "readable_payloads": []
        }

        # 逐层解析
        for layer in packet.layers:
            layer_name = layer.layer_name
            layer_info = self._parse_layer(layer, layer_name)
            result["layers"][layer_name] = layer_info

        # 获取完整的原始数据
        result["raw_hex"] = self._get_full_hex_dump(packet)
        result["raw_text_preview"] = self._get_raw_text_preview(packet)
        result["payload"] = self._extract_full_payload(packet)
        result["printable_strings"] = self._extract_printable_strings(packet)
        result["readable_payloads"] = self._extract_readable_payloads(packet)

        return result
    
    def _parse_layer(self, layer, layer_name):
        """解析单个协议层的所有字段"""
        layer_data = {
            "name": layer_name,
            "fields": {}
        }
        
        # 使用不同的方法根据协议类型
        if layer_name == "IP" or layer_name == "IPv4":
            layer_data["fields"] = self._parse_ip_layer(layer)
        elif layer_name == "TCP":
            layer_data["fields"] = self._parse_tcp_layer(layer)
        elif layer_name == "UDP":
            layer_data["fields"] = self._parse_udp_layer(layer)
        elif layer_name == "HTTP":
            layer_data["fields"] = self._parse_http_layer(layer)
        elif layer_name == "DNS":
            layer_data["fields"] = self._parse_dns_layer(layer)
        elif layer_name == "ARP":
            layer_data["fields"] = self._parse_arp_layer(layer)
        elif layer_name == "ICMP" or layer_name == "ICMPv6":
            layer_data["fields"] = self._parse_icmp_layer(layer)
        else:
            # 通用解析方式
            layer_data["fields"] = self._parse_generic_layer(layer)

        decoded_fields = self._decode_hex_fields(layer_data["fields"])
        if decoded_fields:
            layer_data["decoded_fields"] = decoded_fields

        return layer_data
    
    def _parse_ip_layer(self, layer):
        """解析IP层"""
        return {
            "version": str(getattr(layer, 'version', 'N/A')),
            "header_length": str(getattr(layer, 'hdr_len', 'N/A')),
            "dscp": str(getattr(layer, 'dscp', 'N/A')),
            "total_length": str(getattr(layer, 'len', 'N/A')),
            "identification": str(getattr(layer, 'id', 'N/A')),
            "flags": str(getattr(layer, 'flags', 'N/A')),
            "fragment_offset": str(getattr(layer, 'frag_offset', 'N/A')),
            "ttl": str(getattr(layer, 'ttl', 'N/A')),
            "protocol": str(getattr(layer, 'proto', 'N/A')),
            "checksum": str(getattr(layer, 'checksum', 'N/A')),
            "src_ip": str(getattr(layer, 'src', 'N/A')),
            "dst_ip": str(getattr(layer, 'dst', 'N/A')),
        }
    
    def _parse_tcp_layer(self, layer):
        """解析TCP层"""
        return {
            "src_port": str(getattr(layer, 'srcport', 'N/A')),
            "dst_port": str(getattr(layer, 'dstport', 'N/A')),
            "sequence_number": str(getattr(layer, 'seq', 'N/A')),
            "acknowledgment_number": str(getattr(layer, 'ack', 'N/A')),
            "header_length": str(getattr(layer, 'hdr_len', 'N/A')),
            "flags": str(getattr(layer, 'flags', 'N/A')),
            "window_size": str(getattr(layer, 'window_size', 'N/A')),
            "checksum": str(getattr(layer, 'checksum', 'N/A')),
            "urgent_pointer": str(getattr(layer, 'urgent_pointer', 'N/A')),
            "options": self._parse_tcp_options(layer),
            "payload_size": str(getattr(layer, 'len', 'N/A')),
        }
    
    def _parse_tcp_options(self, layer):
        """解析TCP选项"""
        options = {}
        try:
            # 获取所有TCP选项
            if hasattr(layer, 'option_mss'):
                options['MSS'] = str(getattr(layer, 'option_mss', 'N/A'))
            if hasattr(layer, 'option_wscale'):
                options['WSCALE'] = str(getattr(layer, 'option_wscale', 'N/A'))
            if hasattr(layer, 'option_sack_perm'):
                options['SACK_PERM'] = 'present'
            if hasattr(layer, 'option_timestamps'):
                options['TIMESTAMPS'] = str(getattr(layer, 'option_timestamps', 'N/A'))
        except:
            pass
        return options
    
    def _parse_udp_layer(self, layer):
        """解析UDP层"""
        return {
            "src_port": str(getattr(layer, 'srcport', 'N/A')),
            "dst_port": str(getattr(layer, 'dstport', 'N/A')),
            "length": str(getattr(layer, 'len', 'N/A')),
            "checksum": str(getattr(layer, 'checksum', 'N/A')),
        }
    
    def _parse_http_layer(self, layer):
        """解析HTTP层"""
        http_data = {}
        
        # 请求行
        if hasattr(layer, 'request_method'):
            http_data['method'] = str(getattr(layer, 'request_method', 'N/A'))
        if hasattr(layer, 'request_uri'):
            http_data['uri'] = str(getattr(layer, 'request_uri', 'N/A'))
        if hasattr(layer, 'request_version'):
            http_data['version'] = str(getattr(layer, 'request_version', 'N/A'))
        
        # 响应行
        if hasattr(layer, 'response_code'):
            http_data['status_code'] = str(getattr(layer, 'response_code', 'N/A'))
        if hasattr(layer, 'response_phrase'):
            http_data['reason'] = str(getattr(layer, 'response_phrase', 'N/A'))
        
        # 请求头
        headers = {}
        for attr in dir(layer):
            if 'request_' in attr and 'header' in attr.lower():
                try:
                    value = getattr(layer, attr)
                    header_name = attr.replace('request_', '').replace('_', '-').upper()
                    headers[header_name] = str(value)
                except:
                    pass
        
        if headers:
            http_data['headers'] = headers
        
        # 请求体
        if hasattr(layer, 'file_data'):
            http_data['body'] = str(getattr(layer, 'file_data', 'N/A'))[:500]  # 限制大小
        
        return http_data
    
    def _parse_dns_layer(self, layer):
        """解析DNS层"""
        dns_data = {
            "transaction_id": str(getattr(layer, 'id', 'N/A')),
            "flags": str(getattr(layer, 'flags', 'N/A')),
            "questions": [],
            "answers": [],
            "authorities": [],
            "additionals": []
        }
        
        try:
            # 解析问题部分
            if hasattr(layer, 'qry_name'):
                dns_data['questions'].append({
                    'name': str(getattr(layer, 'qry_name', 'N/A')),
                    'type': str(getattr(layer, 'qry_type', 'N/A')),
                    'class': str(getattr(layer, 'qry_class', 'N/A'))
                })
            
            # 解析回答部分
            if hasattr(layer, 'resp_name'):
                dns_data['answers'].append({
                    'name': str(getattr(layer, 'resp_name', 'N/A')),
                    'type': str(getattr(layer, 'resp_type', 'N/A')),
                    'class': str(getattr(layer, 'resp_class', 'N/A')),
                    'ttl': str(getattr(layer, 'resp_ttl', 'N/A')),
                    'data': str(getattr(layer, 'resp_addr', 'N/A'))
                })
        except:
            pass
        
        return dns_data
    
    def _parse_arp_layer(self, layer):
        """解析ARP层"""
        return {
            "hardware_type": str(getattr(layer, 'hw_type', 'N/A')),
            "protocol_type": str(getattr(layer, 'proto_type', 'N/A')),
            "operation": str(getattr(layer, 'opcode', 'N/A')),
            "src_hw_addr": str(getattr(layer, 'src_hw_addr', 'N/A')),
            "src_proto_addr": str(getattr(layer, 'src_proto_addr', 'N/A')),
            "dst_hw_addr": str(getattr(layer, 'dst_hw_addr', 'N/A')),
            "dst_proto_addr": str(getattr(layer, 'dst_proto_addr', 'N/A')),
        }
    
    def _parse_icmp_layer(self, layer):
        """解析ICMP层"""
        return {
            "type": str(getattr(layer, 'type', 'N/A')),
            "code": str(getattr(layer, 'code', 'N/A')),
            "checksum": str(getattr(layer, 'checksum', 'N/A')),
            "rest_of_header": str(getattr(layer, 'rest_of_header', 'N/A')),
        }
    
    def _parse_generic_layer(self, layer):
        """通用层解析 - 适用于所有其他协议"""
        fields = {}
        
        try:
            # 获取层的所有非私有属性
            for attr in dir(layer):
                if not attr.startswith('_'):
                    try:
                        value = getattr(layer, attr)
                        # 只保留基本类型的值
                        if isinstance(value, (str, int, float, bool)):
                            fields[attr] = str(value)
                    except:
                        pass
        except:
            pass
        
        return fields

    def _decode_hex_fields(self, fields):
        """尝试将字段中的十六进制字符串解码为可读文本"""
        decoded = {}
        if not isinstance(fields, dict):
            return decoded

        hex_chars = set("0123456789abcdefABCDEF")
        for key, value in fields.items():
            if not isinstance(value, str):
                continue
            cleaned = value.replace("0x", "").replace("0X", "").replace(":", "").replace(" ", "")
            if len(cleaned) < 8 or len(cleaned) % 2 != 0:
                continue
            if any(c not in hex_chars for c in cleaned):
                continue
            text = self._decode_hex_to_text(cleaned, max_len=400)
            if not text:
                continue
            visible = sum(1 for ch in text if ch.isalnum() or ch in " _-{}:;,.@/\\")
            if visible >= 4:
                decoded[key] = text

        return decoded
    
    def _get_full_hex_dump(self, packet, bytes_per_line=16):
        """获取完整的十六进制转储（所有原始数据）"""
        try:
            raw_data = bytes.fromhex(packet.get_raw_packet().hex())
            hex_lines = []
            
            for i in range(0, len(raw_data), bytes_per_line):
                chunk = raw_data[i:i+bytes_per_line]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                hex_lines.append(f"{i:08x}:  {hex_part:<{bytes_per_line*3}}  {ascii_part}")
            
            return '\n'.join(hex_lines)
        except:
            return ""

    def _get_raw_text_preview(self, packet, max_len=800):
        """获取原始payload的可读文本预览（utf-8解码，回退为可打印字符）"""
        try:
            raw_data = packet.get_raw_packet() if hasattr(packet, "get_raw_packet") else b""
            text = raw_data.decode('utf-8', errors='ignore')
            text = self._to_printable_text(text)
            if not text.strip():
                text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_data)
            return self._to_printable_text(text, max_len=max_len)
        except:
            pass

        try:
            tcp_bytes = self._get_tcp_segment(packet)
            return self._decode_bytes_to_text(tcp_bytes, max_len=max_len)
        except:
            return ""

    def _extract_printable_strings(self, packet, min_len=4, max_total_len=2000):
        """提取类似Wireshark可见字符串的明文片段（仅可打印ASCII）"""
        try:
            raw_data = packet.get_raw_packet() if hasattr(packet, "get_raw_packet") else b""
        except Exception:
            raw_data = b""

        try:
            tcp_bytes = self._get_tcp_segment(packet)
            if tcp_bytes:
                raw_data = tcp_bytes
        except Exception:
            pass

        if not raw_data:
            return ""

        parts = []
        buf = []
        total_len = 0
        for b in raw_data:
            if 32 <= b < 127:
                buf.append(chr(b))
            else:
                if len(buf) >= min_len:
                    segment = ''.join(buf)
                    parts.append(segment)
                    total_len += len(segment)
                    if total_len >= max_total_len:
                        break
                buf = []

        if buf and len(buf) >= min_len and total_len < max_total_len:
            parts.append(''.join(buf))

        text = "\n".join(parts)
        if len(text) > max_total_len:
            text = text[:max_total_len] + "...(truncated)"
        return text

    def _extract_full_payload(self, packet):
        """提取完整的payload数据"""
        payload_info = {
            "layers_with_payload": [],
            "total_payload_size": 0
        }
        
        try:
            # 检查TCP payload
            if hasattr(packet, 'tcp'):
                if hasattr(packet.tcp, 'payload'):
                    payload_hex = str(getattr(packet.tcp, 'payload', ''))
                    tcp_bytes = self._get_tcp_segment(packet)
                    payload_info["layers_with_payload"].append({
                        "layer": "TCP",
                        "size": len(payload_hex) // 2,
                        "hex": payload_hex[:200],  # 前100字节
                        "ascii": self._hex_to_ascii(payload_hex[:200]),
                        "text": self._decode_bytes_to_text(tcp_bytes)
                    })
                    payload_info["total_payload_size"] += len(payload_hex) // 2

            # 检查UDP payload
            if hasattr(packet, 'udp'):
                if hasattr(packet.udp, 'payload'):
                    payload_hex = str(getattr(packet.udp, 'payload', ''))
                    payload_info["layers_with_payload"].append({
                        "layer": "UDP",
                        "size": len(payload_hex) // 2,
                        "hex": payload_hex[:200],
                        "ascii": self._hex_to_ascii(payload_hex[:200]),
                        "text": self._decode_hex_to_text(payload_hex)
                    })
                    payload_info["total_payload_size"] += len(payload_hex) // 2

            # 检查HTTP payload
            if hasattr(packet, 'http'):
                if hasattr(packet.http, 'file_data'):
                    payload_hex = str(getattr(packet.http, 'file_data', ''))
                    payload_info["layers_with_payload"].append({
                        "layer": "HTTP",
                        "size": len(payload_hex) // 2,
                        "hex": payload_hex[:200],
                        "ascii": self._hex_to_ascii(payload_hex[:200]),
                        "text": self._decode_hex_to_text(payload_hex)
                    })
                    payload_info["total_payload_size"] += len(payload_hex) // 2

            # 检查通用data层
            if hasattr(packet, 'data'):
                payload_hex = str(getattr(packet.data, 'data', ''))
                payload_info["layers_with_payload"].append({
                    "layer": "DATA",
                    "size": len(payload_hex) // 2,
                    "hex": payload_hex[:200],
                    "ascii": self._hex_to_ascii(payload_hex[:200]),
                    "text": self._decode_hex_to_text(payload_hex)
                })
                payload_info["total_payload_size"] += len(payload_hex) // 2

        except Exception as e:
            print(f"提取payload失败: {e}")
        
        return payload_info
    
    def _hex_to_ascii(self, hex_str):
        """将十六进制字符串转换为ASCII"""
        try:
            data = bytes.fromhex(hex_str.replace(' ', '').replace(':', ''))
            return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        except:
            return ""

    def _decode_hex_to_text(self, hex_str, max_len=4000):
        """将十六进制字符串转换为可读文本（utf-8），用于AI友好输出"""
        try:
            if hex_str is None:
                return ""
            cleaned = str(hex_str).replace(' ', '').replace(':', '')
            if not cleaned:
                return ""
            text = bytes.fromhex(cleaned).decode('utf-8', errors='ignore')
            text = self._to_printable_text(text)
            if len(text) > max_len:
                return text[:max_len] + "...(truncated)"
            return text
        except:
            return ""

    def _decode_bytes_to_text(self, data_bytes, max_len=4000):
        """将字节数据转换为可读文本（utf-8），用于AI友好输出"""
        try:
            if not data_bytes:
                return ""
            text = data_bytes.decode('utf-8', errors='ignore')
            text = self._to_printable_text(text)
            if not text.strip():
                text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data_bytes)
            if len(text) > max_len:
                return text[:max_len] + "...(truncated)"
            return text
        except:
            return ""

    def _to_printable_text(self, text, max_len=None):
        """将不可见字符替换为 '.'，避免JSON中出现控制字符转义"""
        if text is None:
            return ""
        safe_chars = []
        for ch in str(text):
            code = ord(ch)
            if ch in ("\n", "\r", "\t"):
                safe_chars.append(ch)
            elif 32 <= code < 127:
                safe_chars.append(ch)
            else:
                safe_chars.append(".")
        safe_text = "".join(safe_chars)
        if max_len and len(safe_text) > max_len:
            return safe_text[:max_len] + "...(truncated)"
        return safe_text

    def _get_tcp_segment(self, packet):
        """本地解码TCP十六进制payload为原始字节"""
        try:
            payload = get_tcp_segment(packet)
            if payload:
                return payload
        except Exception:
            return b""
        return b""

    def _extract_readable_payloads(self, packet, max_len=2000):
        """按协议类型提取可读payload文本，优先解码"""
        readable = []

        def add_payload(source, raw_value):
            if raw_value is None:
                return
            raw_str = str(raw_value)
            text = self._decode_hex_to_text(raw_str, max_len=max_len)
            if not text:
                # 如果不是hex，直接取可打印字符
                text = self._to_printable_text(raw_str)
            if text:
                readable.append({
                    "source": source,
                    "text": self._to_printable_text(text, max_len=max_len),
                    "raw_preview": raw_str[:200]
                })

        try:
            # TCP 重组字段
            if hasattr(packet, 'tcp'):
                tcp_bytes = self._get_tcp_segment(packet)
                tcp_text = self._decode_bytes_to_text(tcp_bytes, max_len=max_len)
                if tcp_text:
                    readable.append({
                        "source": "TCP.payload",
                        "text": self._to_printable_text(tcp_text, max_len=max_len),
                        "raw_preview": str(getattr(packet.tcp, 'payload', ''))[:200]
                    })
                for field in ['payload', 'segment_data', 'reassembled_data']:
                    if hasattr(packet.tcp, field):
                        add_payload(f"TCP.{field}", getattr(packet.tcp, field))

            if hasattr(packet, 'udp') and hasattr(packet.udp, 'payload'):
                add_payload("UDP.payload", getattr(packet.udp, 'payload', ''))

            # HTTP 明文字段
            if hasattr(packet, 'http'):
                for field in ['file_data', 'request_full_uri', 'request_uri', 'request_body', 'response_phrase', 'response_code', 'user_agent']:
                    if hasattr(packet.http, field):
                        add_payload(f"HTTP.{field}", getattr(packet.http, field))

            # 通用 data 层
            if hasattr(packet, 'data') and hasattr(packet.data, 'data'):
                add_payload("DATA.data", getattr(packet.data, 'data', ''))

        except Exception as e:
            print(f"提取可读payload失败: {e}")

        return readable
    
    def decompile_packets_bulk(self, packets, max_packets=None):
        """
        批量解包
        
        Args:
            packets: 数据包列表
            max_packets: 最多解包数量（None表示全部）
        """
        results = []
        
        for i, packet in enumerate(packets):
            if max_packets and i >= max_packets:
                break
            
            try:
                result = self.decompile_packet(packet)
                results.append(result)
            except Exception as e:
                print(f"解包数据包失败: {e}")
                continue
        
        return results
    
    def format_for_ai_analysis(self, decompiled_packets):
        """
        将解包结果格式化为AI分析用的文本格式
        """
        formatted = []
        
        for packet_data in decompiled_packets:
            text = f"""
【数据包 #{packet_data['packet_id']}】
时间: {packet_data['timestamp']}
长度: {packet_data['packet_length']} 字节
协议栈: {' → '.join(packet_data['protocols'])}

【协议层详解】
"""
            
            # 添加各层详细信息
            for layer_name, layer_info in packet_data['layers'].items():
                text += f"\n{layer_name}层:\n"
                for field, value in layer_info['fields'].items():
                    text += f"  {field}: {value}\n"
            
            # 添加十六进制转储（前512字节）
            if packet_data.get('raw_hex'):
                hex_lines = packet_data['raw_hex'].split('\n')[:32]  # 前32行
                text += f"\n【十六进制转储】(前{len(hex_lines)*16}字节):\n"
                text += '\n'.join(hex_lines[:10]) + "\n"
                if len(hex_lines) > 10:
                    text += f"... 还有 {len(hex_lines) - 10} 行 ...\n"
            if packet_data.get('raw_text_preview'):
                text += "\n【原始文本预览】(已尝试UTF-8解码，截断展示):\n"
                preview = packet_data['raw_text_preview']
                text += preview if len(preview) <= 800 else preview[:800] + "\n...(truncated)...\n"
            if packet_data.get('printable_strings'):
                text += "\n【可见字符串】(类似Wireshark可读片段):\n"
                text += packet_data['printable_strings'][:1200] + "\n"

            # 添加payload信息
            if packet_data.get('payload', {}).get('layers_with_payload'):
                text += f"\n【Payload信息】\n"
                text += f"总大小: {packet_data['payload']['total_payload_size']} 字节\n"
                for payload in packet_data['payload']['layers_with_payload']:
                    text += f"  {payload['layer']}: {payload['size']} 字节\n"
                    if payload['hex']:
                        text += f"    Hex: {payload['hex']}\n"
                        text += f"    ASCII: {payload['ascii']}\n"
                    if payload.get('text'):
                        text += f"    Text: {payload['text']}\n"

            if packet_data.get('readable_payloads'):
                text += "\n【可读Payload摘录】\n"
                for rp in packet_data['readable_payloads'][:5]:
                    text += f"  - 来源: {rp['source']} | 预览: {rp['text'][:300]}\n"

            text += "\n" + "="*60 + "\n"
            formatted.append(text)
        
        return '\n'.join(formatted)
