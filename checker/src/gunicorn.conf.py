import multiprocessing
import math

worker_class = "uvicorn_worker.UvicornH11Worker"
workers = math.ceil(multiprocessing.cpu_count() / 2)
threads = 4
bind = "0.0.0.0:8000"
timeout = 90
keepalive = 3600
preload_app = True