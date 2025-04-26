from concurrent.futures import ThreadPoolExecutor

def parallel_map(func, items, max_workers=10):
    """
    Applies 'func' to each item in 'items' concurrently using ThreadPoolExecutor.
    Returns a list of results in the same order as 'items'.
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for result in executor.map(func, items):
            results.append(result)
    return results

def parallel_run(func, args_list, max_workers=10):
    """
    Runs 'func' for each tuple of arguments in 'args_list' concurrently.
    'args_list' should be an iterable of argument tuples.
    Returns a list of results corresponding to each function call.
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(func, *args) for args in args_list]
        for future in futures:
            results.append(future.result())
    return results
