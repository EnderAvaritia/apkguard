"""网络流量抓包（C2 端点核心证据）。

方案：在宿主机起一个 HTTP 代理，通过 `adb shell settings put global http_proxy`
把设备的全局代理指向它。代理采集两类证据：
  - HTTP 请求：完整 URL（含 query）→ 端点
  - HTTPS CONNECT：目标 host:port（TLS SNI 级别证据）→ 端点；随后建立原始
    TCP 隧道保证 App 的 HTTPS 请求可正常完成，不破坏样本网络行为。

端口绑定、转发、隧道全部 best-effort：任何一步失败只记录，绝不让代理崩溃，
也绝不阻断样本运行。
"""
from __future__ import annotations

import http.server
import select
import socket
import threading
import urllib.request
from typing import Optional

# 代理响应体：尽可能小，避免干扰 App 解析
_EMPTY_HTML = b"<html><body></body></html>"


def detect_host_ip() -> Optional[str]:
    """探测宿主机在局域网内的 IP（供真机经代理回连）；失败返回 None"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))  # 只做路由选择，不实际发包
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def resolve_proxy_target(serial: str, host_ip: str, port: int) -> Optional[str]:
    """计算设备应使用的代理地址 host:port。

    - 模拟器（emulator-*）：宿主环回别名 10.0.2.2，恒可用
    - 真机：需要宿主机局域网 IP（配置 host_ip 优先，否则自动探测）
    无法确定时返回 None（调用方跳过抓包，不阻断流程）。
    """
    if serial.startswith("emulator-"):
        return f"10.0.2.2:{port}"
    if host_ip:
        return f"{host_ip}:{port}"
    detected = detect_host_ip()
    if detected:
        return f"{detected}:{port}"
    return None


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    """记录端点并透传（HTTP 转发 / HTTPS 隧道）"""

    server_version = "apkguard-capture/1.0"  # type: ignore[assignment]

    # ---- 记录 ----

    def _record(self, endpoint: str) -> None:
        cap: "ProxyCapture" = self.server.capture  # type: ignore[attr-defined]
        cap.record(endpoint)

    # ---- HTTP 方法 ----

    def do_GET(self) -> None:  # noqa: N802
        self._handle_http()

    def do_POST(self) -> None:  # noqa: N802
        self._handle_http()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle_http()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle_http()

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_http()

    def do_CONNECT(self) -> None:  # noqa: N802
        self._handle_connect()

    # ---- 实现 ----

    def _handle_http(self) -> None:
        try:
            # 代理模式下请求行是绝对形式（http://host/path）；直接模式是 origin 形式
            if self.path.startswith(("http://", "https://")):
                target = self.path
            else:
                target = f"http://{self.headers.get('Host', '')}{self.path}"
            self._record(target)
            body = self._read_body()
            req = urllib.request.Request(
                target,
                data=body,
                headers={k: v for k, v in self.headers.items() if k.lower() != "host"},
                method=self.command,
            )
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                status = resp.status
                headers = dict(resp.headers.items())
                payload = resp.read()
        except Exception:
            status, headers, payload = 502, {}, b"<html><body>bad gateway</body></html>"
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_body(self) -> Optional[bytes]:
        length = self.headers.get("Content-Length")
        if not length:
            return None
        try:
            return self.rfile.read(int(length))
        except (ValueError, OSError):
            return None

    def _handle_connect(self) -> None:
        endpoint = self.path  # 形如 host:port
        self._record(endpoint)
        # 建立到目标的原始 TCP 连接，成功后双向隧道（best-effort）
        host, _, port = endpoint.rpartition(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError:
            self.send_response(502)
            self.end_headers()
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        self._tunnel(upstream)

    def _tunnel(self, upstream: socket.socket) -> None:
        """双向转发字节流，直到任一端关闭（HTTPS 透传）"""
        socks = [self.connection, upstream]
        try:
            while True:
                readable, _, _ = select.select(socks, [], [], 30)
                if not readable:
                    continue
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    target = upstream if sock is self.connection else self.connection
                    target.sendall(data)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        # 关闭默认访问日志，避免刷屏
        pass


class ProxyCapture:
    """宿主机代理抓包：线程安全地记录去重端点"""

    def __init__(self, port: int = 8080):
        self.port = port
        self._lock = threading.Lock()
        self._endpoints: list[str] = []
        self._count = 0
        self._server: Optional[http.server.ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # ---- 生命周期 ----

    def start(self) -> bool:
        """启动代理；端口被占用等失败返回 False（不阻断主流程）"""
        try:
            server = http.server.ThreadingHTTPServer(("0.0.0.0", self.port), _ProxyHandler)
        except OSError:
            return False
        server.capture = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    # ---- 记录 ----

    def record(self, endpoint: str) -> None:
        with self._lock:
            self._count += 1
            if endpoint not in self._endpoints:
                self._endpoints.append(endpoint)

    @property
    def endpoints(self) -> list[str]:
        with self._lock:
            return list(self._endpoints)

    @property
    def count(self) -> int:
        with self._lock:
            return self._count
