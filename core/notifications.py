from collections import deque
from threading import Lock

# Simple in-memory notification queues for real-time pushes to WebSocket
_queue = deque()
_lock = Lock()

def push_flow(flow):
    with _lock:
        _queue.append({'type': 'flow', 'data': flow})

def push_phishing(scan):
    with _lock:
        _queue.append({'type': 'phishing', 'data': scan})

def push_vulnerability(scan):
    with _lock:
        _queue.append({'type': 'vulnerability', 'data': scan})

def pop_all():
    items = []
    with _lock:
        while _queue:
            items.append(_queue.popleft())
    return items
