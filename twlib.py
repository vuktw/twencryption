from datetime import timedelta
import functools
import threading
import time

def runtime(func):
    """print run time of function"""

    @functools.wraps(func)
    def wrapper_decorator(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        elapsed_seconds = end_time - start_time
        formatted_time = str(timedelta(seconds=int(elapsed_seconds)))
        print(f"{func.__name__}() run time: {formatted_time}")
        return result

    return wrapper_decorator

def progress(func):
    """print progress of function"""

    @functools.wraps(func)
    def wrapper_decorator(*args, **kwargs):
        result_container = []

        def worker():
            result = func(*args, **kwargs)
            result_container.append(result)

        background_thread = threading.Thread(target=worker)
        start_thread_time = time.time()
        background_thread.start()

        while background_thread.is_alive():
            elapsed_time = time.time() - start_thread_time
            minutes = int(elapsed_time // 60)
            seconds = int(elapsed_time % 60)
            print(f"\r{func.__name__}() - time elapsed: {minutes:02d}:{seconds:02d}", end="", flush=True)
            time.sleep(0.001)

        background_thread.join()
        print(f"\n{func.__name__}() finished")
        result = result_container[0]
        return result

    return wrapper_decorator

@runtime
def long_function1():
    time.sleep(3)

@progress
def long_function2():
    time.sleep(3)

@runtime
@progress
def long_function3():
    time.sleep(3)

if __name__ == "__main__":
    long_function1()
    long_function2()
    long_function3()
