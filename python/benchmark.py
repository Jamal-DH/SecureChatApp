from multiprocessing import Process
import time

def counter(num):
    count = 0
    while count < num:
        count += 1

def run_benchmark(processes, count_per_process, repeat=3):
    timings = []

    for _ in range(repeat):
        start_time = time.perf_counter()

        process_list = []
        for _ in range(processes):
            process = Process(target=counter, args=(count_per_process,))
            process_list.append(process)
            process.start()

        for process in process_list:
            process.join()

        end_time = time.perf_counter()
        elapsed_time = end_time - start_time
        timings.append(elapsed_time)

        print(f"Iteration finished in: {elapsed_time:.2f} seconds")

    avg_time = sum(timings) / len(timings)
    print(f"\nAverage time over {repeat} runs: {avg_time:.2f} seconds")
    return avg_time

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CPU Performance Benchmark")
    parser.add_argument("--processes", type=int, default=4, help="Number of processes to run in parallel")
    parser.add_argument("--count", type=int, default=250000000, help="Count limit for each process")
    parser.add_argument("--repeat", type=int, default=3, help="Number of times to repeat the benchmark")

    args = parser.parse_args()

    print(f"Running benchmark with {args.processes} processes, each counting to {args.count}, repeated {args.repeat} times.\n")

    run_benchmark(args.processes, args.count, args.repeat)
