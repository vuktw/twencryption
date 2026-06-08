from datetime import timedelta
import functools
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
        print(f"{func.__name__} run time: {formatted_time}")
        return result

    return wrapper_decorator

@runtime
def long_function():
    time.sleep(3)

if __name__ == "__main__":
    long_function()

