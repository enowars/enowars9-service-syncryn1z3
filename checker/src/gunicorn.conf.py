import multiprocessing

worker_class = "uvicorn.workers.UvicornWorker"
workers = max(1, multiprocessing.cpu_count() - 1)
bind = "0.0.0.0:8000"
timeout = 90
keepalive = 3600
preload_app = True